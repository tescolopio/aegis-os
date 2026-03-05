"""Regression guard – ensures the router always routes LLM execution through
``orchestrator.run()`` and never calls governance modules directly.

Any of the following would break this test and is intentional:
  * The execute_task endpoint calling Guardrails, PolicyEngine, or
    SessionManager directly (bypassing the orchestrator).
  * The execute_task endpoint delegating to a different method than `run()`.

Run with:
    pytest tests/test_orchestrator_no_bypass.py -v
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import src.control_plane.router as router_module
from src.adapters.base import LLMResponse
from src.control_plane.orchestrator import Orchestrator, OrchestratorRequest, OrchestratorResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GOVERNANCE_MODULE_PREFIXES = (
    "src.governance.guardrails",
    "src.governance.policy_engine",
    "src.governance.session_mgr",
)

_EXECUTE_ROUTE_HANDLER = "execute_task"


def _stub_result() -> OrchestratorResult:
    return OrchestratorResult(
        task_id=uuid4(),
        response=LLMResponse(
            content="stub response",
            tokens_used=5,
            model="gpt-4o-mini",
            provider="stub",
            finish_reason="stop",
        ),
        session_token="stub.token",
        sanitized_prompt="stub prompt",
    )


# ---------------------------------------------------------------------------
# Test 1 – Router calls orchestrator.run() for /tasks/execute
# ---------------------------------------------------------------------------


class TestRouterDelegatesToOrchestrator:
    """Verify the execute_task route handler delegates to orchestrator.run()."""

    @pytest.mark.asyncio
    async def test_execute_task_calls_orchestrator_run(self) -> None:
        """Patch ``_orchestrator`` on the router module; assert ``.run()`` is invoked."""
        mock_orc = MagicMock(spec=Orchestrator)
        mock_orc.run = AsyncMock(return_value=_stub_result())

        # Inject the mock orchestrator into the router
        original = router_module._orchestrator
        router_module._orchestrator = mock_orc

        try:
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router_module.router)
            client = TestClient(app, raise_server_exceptions=True)

            resp = client.post(
                "/tasks/execute",
                json={
                    "prompt": "What is 2+2?",
                    "agent_type": "general",
                    "requester_id": "regression-test-user",
                },
            )

            assert resp.status_code == 200, (
                f"Expected 200, got {resp.status_code}: {resp.text}"
            )
            mock_orc.run.assert_called_once()
            call_args = mock_orc.run.call_args
            assert call_args is not None, "orchestrator.run() was not called"
            # The first positional/keyword arg must be an OrchestratorRequest
            orchestrator_req = (
                call_args.args[0] if call_args.args else call_args.kwargs.get("request")
            )
            assert isinstance(orchestrator_req, OrchestratorRequest), (
                f"orchestrator.run() must receive an OrchestratorRequest; "
                f"got {type(orchestrator_req)}"
            )
        finally:
            router_module._orchestrator = original

    @pytest.mark.asyncio
    async def test_execute_task_without_orchestrator_returns_500(self) -> None:
        """If no orchestrator is configured, the endpoint must not silently succeed."""
        original = router_module._orchestrator
        router_module._orchestrator = None

        try:
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router_module.router)
            # raise_server_exceptions=False so we can inspect the 500
            client = TestClient(app, raise_server_exceptions=False)

            resp = client.post(
                "/tasks/execute",
                json={
                    "prompt": "hello",
                    "agent_type": "general",
                    "requester_id": "user-x",
                },
            )
            assert resp.status_code == 500
        finally:
            router_module._orchestrator = original


# ---------------------------------------------------------------------------
# Test 2 – execute_task route handler must not directly call governance modules
# ---------------------------------------------------------------------------


class TestNoDirectGovernanceCallsInExecuteRoute:
    """Static analysis: the execute_task function body must not reference
    governance modules directly.  Any such reference is a bypass of the
    orchestrator contract.
    """

    def _get_execute_task_source(self) -> str:
        """Extract the source of the execute_task function."""
        func = getattr(router_module, _EXECUTE_ROUTE_HANDLER, None)
        assert func is not None, (
            f"Route handler '{_EXECUTE_ROUTE_HANDLER}' not found in router module"
        )
        # Unwrap FastAPI decorators if necessary
        raw = func
        while hasattr(raw, "__wrapped__"):
            raw = raw.__wrapped__
        return inspect.getsource(raw)

    def test_execute_task_does_not_import_guardrails(self) -> None:
        src = self._get_execute_task_source()
        assert "Guardrails" not in src, (
            "execute_task must not reference Guardrails directly – use orchestrator.run()"
        )

    def test_execute_task_does_not_reference_policy_engine(self) -> None:
        src = self._get_execute_task_source()
        assert "PolicyEngine" not in src, (
            "execute_task must not reference PolicyEngine directly – use orchestrator.run()"
        )

    def test_execute_task_does_not_reference_session_mgr_directly(self) -> None:
        src = self._get_execute_task_source()
        # The handler may mention '_session_mgr' only indirectly (module-level var),
        # but it must not call session_mgr methods directly.
        assert "issue_token" not in src, (
            "execute_task must not call issue_token() directly – use orchestrator.run()"
        )
        assert "validate_token" not in src, (
            "execute_task must not call validate_token() directly – use orchestrator.run()"
        )

    def test_execute_task_does_not_call_sanitize_directly(self) -> None:
        src = self._get_execute_task_source()
        assert "sanitize" not in src, (
            "execute_task must not call sanitize() directly – use orchestrator.run()"
        )

    def test_execute_task_calls_orc_run(self) -> None:
        """The source of execute_task must contain a call to orchestrator .run()."""
        src = self._get_execute_task_source()
        assert "orc.run(" in src or "orchestrator.run(" in src, (
            "execute_task must explicitly call orc.run() or orchestrator.run(); "
            "direct calls to governance modules are forbidden"
        )


# ---------------------------------------------------------------------------
# Test 3 – Router module-level governance imports are NOT used in execute path
# ---------------------------------------------------------------------------


class TestRouterModuleImports:
    """Verify the router module's governance imports are not wired into execute_task."""

    def test_router_module_imports_orchestrator(self) -> None:
        """The router must import the Orchestrator, not bypass it."""
        assert hasattr(router_module, "Orchestrator"), (
            "router module must import Orchestrator from control_plane.orchestrator"
        )

    def test_router_module_imports_orchestrator_request(self) -> None:
        assert hasattr(router_module, "OrchestratorRequest"), (
            "router module must import OrchestratorRequest to build the input for run()"
        )

    def test_governance_modules_not_imported_in_execute_handler_ast(self) -> None:
        """Parse the router source and confirm execute_task's AST does not reference
        governance-module attribute paths like ``guardrails.sanitize``."""
        router_source = Path(router_module.__file__).read_text()  # type: ignore[arg-type]
        tree = ast.parse(router_source)

        # Find the execute_task function node
        execute_fn: ast.AsyncFunctionDef | None = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == _EXECUTE_ROUTE_HANDLER:
                execute_fn = node
                break
        assert execute_fn is not None, f"Could not find {_EXECUTE_ROUTE_HANDLER} in AST"

        # Collect all attribute accesses inside the function
        forbidden_attrs = {
            "check_prompt_injection",
            "mask_pii",
            "sanitize",
            "issue_token",
            "validate_token",
            "evaluate",
            "is_allowed",
        }
        violations: list[str] = []
        for node in ast.walk(execute_fn):
            if isinstance(node, ast.Attribute) and node.attr in forbidden_attrs:
                violations.append(node.attr)

        assert not violations, (
            f"execute_task directly calls governance methods {violations}; "
            "all governance logic must be encapsulated in orchestrator.run()"
        )
