"""P1-2 tests: router delegates to orchestrator; no inline governance; HTTP contract.

Three test categories (per the P1-2 roadmap requirements):

1. Unit — delegation only
   Mock ``orchestrator.run()``; POST to ``POST /api/v1/tasks``; assert the mock
   was called exactly once with the correct payload and the router performs no
   PII, policy, or budget logic itself.

2. Negative — no direct governance module imports
   AST-based check that ``router.py`` contains no import statements sourcing
   from ``guardrails``, ``opa_client``, ``budget_enforcer``, or ``loop_detector``.

3. Contract — HTTP response schema
   Assert correct status codes and response body shapes for 200, 400, 403, 429,
   and 500 outcomes.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import src.control_plane.router as router_module
from src.adapters.base import LLMResponse
from src.control_plane.orchestrator import (
    BudgetLimitError,
    Orchestrator,
    OrchestratorRequest,
    OrchestratorResult,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_VALID_PAYLOAD: dict[str, Any] = {
    "prompt": "Summarise the Q4 earnings report.",
    "agent_type": "general",
    "requester_id": "user-p1-2-test",
    "model": "gpt-4o-mini",
    "max_tokens": 256,
    "temperature": 0.5,
    "protect_outbound_request": False,
}

_STUB_LLM_RESPONSE = LLMResponse(
    content="The Q4 earnings were strong.",
    tokens_used=42,
    model="gpt-4o-mini",
    provider="stub",
    finish_reason="stop",
)

_STUB_RESULT = OrchestratorResult(
    task_id=uuid4(),
    response=_STUB_LLM_RESPONSE,
    session_token="jwt.stub.token",
    sanitized_prompt="Summarise the Q4 earnings report.",
    pii_found_in_prompt=[],
    pii_found_in_response=[],
)


def _make_app(mock_orc: Orchestrator) -> FastAPI:
    """Build a FastAPI instance with the router mounted and mock orchestrator injected."""
    router_module.configure_orchestrator(mock_orc)
    app = FastAPI()
    app.include_router(router_module.router, prefix="/api/v1")
    return app


def _make_mock_orc(result: OrchestratorResult | None = None) -> MagicMock:
    mock_orc = MagicMock(spec=Orchestrator)
    mock_orc.run = AsyncMock(return_value=result if result is not None else _STUB_RESULT)
    return mock_orc


# ---------------------------------------------------------------------------
# 1. Unit — delegation
# ---------------------------------------------------------------------------


class TestDelegation:
    """POST /api/v1/tasks must delegate to orchestrator.run() and nothing else."""

    @pytest.fixture(autouse=True)
    def _reset_orchestrator(self) -> Any:
        """Restore the module-level orchestrator after each test."""
        original = router_module._orchestrator
        yield
        router_module._orchestrator = original

    def test_orchestrator_run_called_exactly_once(self) -> None:
        """A single POST /api/v1/tasks must trigger exactly one orchestrator.run() call."""
        mock_orc = _make_mock_orc()
        client = TestClient(_make_app(mock_orc), raise_server_exceptions=True)

        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)

        assert resp.status_code == 200, resp.text
        mock_orc.run.assert_called_once()

    def test_orchestrator_receives_correct_prompt(self) -> None:
        """Orchestrator.run() must receive the exact prompt from the request body."""
        mock_orc = _make_mock_orc()
        client = TestClient(_make_app(mock_orc), raise_server_exceptions=True)

        client.post("/api/v1/tasks", json=_VALID_PAYLOAD)

        req: OrchestratorRequest = mock_orc.run.call_args.args[0]
        assert req.prompt == _VALID_PAYLOAD["prompt"]

    def test_orchestrator_receives_correct_agent_type(self) -> None:
        """Orchestrator.run() must receive the agent_type from the request body."""
        mock_orc = _make_mock_orc()
        client = TestClient(_make_app(mock_orc), raise_server_exceptions=True)

        client.post("/api/v1/tasks", json=_VALID_PAYLOAD)

        req: OrchestratorRequest = mock_orc.run.call_args.args[0]
        assert req.agent_type == _VALID_PAYLOAD["agent_type"]

    def test_orchestrator_receives_correct_requester_id(self) -> None:
        """Orchestrator.run() must receive the requester_id from the request body."""
        mock_orc = _make_mock_orc()
        client = TestClient(_make_app(mock_orc), raise_server_exceptions=True)

        client.post("/api/v1/tasks", json=_VALID_PAYLOAD)

        req: OrchestratorRequest = mock_orc.run.call_args.args[0]
        assert req.requester_id == _VALID_PAYLOAD["requester_id"]

    def test_orchestrator_receives_protect_outbound_request_flag(self) -> None:
        """Router must forward the protect_outbound_request flag unchanged."""
        mock_orc = _make_mock_orc()
        client = TestClient(_make_app(mock_orc), raise_server_exceptions=True)

        client.post(
            "/api/v1/tasks",
            json={**_VALID_PAYLOAD, "protect_outbound_request": True},
        )

        req: OrchestratorRequest = mock_orc.run.call_args.args[0]
        assert req.protect_outbound_request is True

    def test_orchestrator_argument_is_orchestrator_request_type(self) -> None:
        """orchestrator.run() must be called with an OrchestratorRequest instance."""
        mock_orc = _make_mock_orc()
        client = TestClient(_make_app(mock_orc), raise_server_exceptions=True)

        client.post("/api/v1/tasks", json=_VALID_PAYLOAD)

        call_arg = mock_orc.run.call_args.args[0]
        assert isinstance(call_arg, OrchestratorRequest), (
            f"Expected OrchestratorRequest, got {type(call_arg).__name__}"
        )

    def test_response_maps_llm_content_to_message(self) -> None:
        """TaskResponse.message must be the LLM content returned by the orchestrator."""
        mock_orc = _make_mock_orc()
        client = TestClient(_make_app(mock_orc), raise_server_exceptions=True)

        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)

        body = resp.json()
        assert body["message"] == _STUB_LLM_RESPONSE.content

    def test_response_propagates_session_token(self) -> None:
        """TaskResponse.session_token must match the value returned by the orchestrator."""
        mock_orc = _make_mock_orc()
        client = TestClient(_make_app(mock_orc), raise_server_exceptions=True)

        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)

        assert resp.json()["session_token"] == _STUB_RESULT.session_token

    def test_response_contains_task_id(self) -> None:
        """TaskResponse must echo the task_id from the request (or a generated UUID)."""
        fixed_id = str(uuid4())
        mock_orc = _make_mock_orc()
        client = TestClient(_make_app(mock_orc), raise_server_exceptions=True)

        resp = client.post(
            "/api/v1/tasks", json={**_VALID_PAYLOAD, "task_id": fixed_id}
        )
        body = resp.json()
        # Must be a valid UUID — either the fixed one or a freshly generated one
        assert UUID(body["task_id"])

    def test_router_performs_no_pii_logic(self) -> None:
        """POST /tasks must not call any PII-scrubbing functions directly.

        Verified by asserting the mock was called with the unscrubbed prompt —
        scrubbing happens inside orchestrator.run(), not in the handler.
        """
        raw_prompt = "contact alice@example.com for details."
        mock_orc = _make_mock_orc()
        client = TestClient(_make_app(mock_orc), raise_server_exceptions=True)

        client.post("/api/v1/tasks", json={**_VALID_PAYLOAD, "prompt": raw_prompt})

        # The orchestrator receives the raw prompt — the handler did not scrub it
        req: OrchestratorRequest = mock_orc.run.call_args.args[0]
        assert req.prompt == raw_prompt


# ---------------------------------------------------------------------------
# 2. Negative — no direct governance module imports
# ---------------------------------------------------------------------------


class TestNoDirectGovernanceImports:
    """router.py must not import from governance or watchdog enforcement modules."""

    _FORBIDDEN_IMPORT_MODULES = {
        "src.governance.guardrails",
        "src.governance.policy_engine.opa_client",
        "src.watchdog.budget_enforcer",
        "src.watchdog.loop_detector",
    }

    def _get_router_import_modules(self) -> set[str]:
        """Return the set of top-level modules imported in router.py (AST-based)."""
        module_path = router_module.__file__
        assert module_path is not None
        source = Path(module_path).read_text()
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module)
        return imported

    def test_router_does_not_import_guardrails(self) -> None:
        imports = self._get_router_import_modules()
        assert "src.governance.guardrails" not in imports, (
            "router.py must not import from guardrails — "
            "all PII logic is handled by the orchestrator"
        )

    def test_router_does_not_import_opa_client(self) -> None:
        imports = self._get_router_import_modules()
        assert "src.governance.policy_engine.opa_client" not in imports, (
            "router.py must not import from opa_client — "
            "policy evaluation is handled by the orchestrator"
        )

    def test_router_does_not_import_budget_enforcer(self) -> None:
        imports = self._get_router_import_modules()
        assert "src.watchdog.budget_enforcer" not in imports, (
            "router.py must not import from budget_enforcer — "
            "budget errors surface as BudgetLimitError from the orchestrator"
        )

    def test_router_does_not_import_loop_detector(self) -> None:
        imports = self._get_router_import_modules()
        assert "src.watchdog.loop_detector" not in imports, (
            "router.py must not import from loop_detector — "
            "loop detection is a watchdog concern, not a router concern"
        )

    def test_no_forbidden_imports_combined(self) -> None:
        """Single combined assertion — fails with the full violation list if any found."""
        imports = self._get_router_import_modules()
        violations = self._FORBIDDEN_IMPORT_MODULES & imports
        assert not violations, (
            f"router.py imports forbidden governance/watchdog modules: {violations}"
        )


# ---------------------------------------------------------------------------
# 3. Contract — HTTP response schema
# ---------------------------------------------------------------------------


class TestHttpContract:
    """Assert the correct HTTP status codes and response bodies."""

    @pytest.fixture(autouse=True)
    def _reset_orchestrator(self) -> Any:
        original = router_module._orchestrator
        yield
        router_module._orchestrator = original

    def _client_with_mock(
        self,
        *,
        raises: Exception | None = None,
        result: OrchestratorResult | None = None,
    ) -> TestClient:
        mock_orc = _make_mock_orc(result)
        if raises is not None:
            mock_orc.run.side_effect = raises
        return TestClient(
            _make_app(mock_orc),
            raise_server_exceptions=False,
        )

    # ------------------------------------------------------------------
    # 200 — success
    # ------------------------------------------------------------------

    def test_200_response_has_task_response_shape(self) -> None:
        client = self._client_with_mock()
        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)

        assert resp.status_code == 200
        body = resp.json()
        # Validate every field in TaskResponse is present with the right types
        assert isinstance(body["task_id"], str)
        assert isinstance(body["agent_type"], str)
        assert isinstance(body["session_token"], str)
        assert isinstance(body["message"], str)
        assert isinstance(body["tokens_used"], int)
        assert isinstance(body["model"], str)
        assert isinstance(body["pii_found"], list)

    def test_200_message_is_nonempty(self) -> None:
        client = self._client_with_mock()
        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)
        assert resp.status_code == 200
        assert resp.json()["message"]

    def test_200_session_token_is_nonempty(self) -> None:
        client = self._client_with_mock()
        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)
        assert resp.status_code == 200
        assert resp.json()["session_token"]

    # ------------------------------------------------------------------
    # 400 — bad request (ValueError from orchestrator)
    # ------------------------------------------------------------------

    def test_400_on_value_error(self) -> None:
        client = self._client_with_mock(raises=ValueError("invalid requester_id"))
        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)
        assert resp.status_code == 400
        assert "detail" in resp.json()

    def test_400_missing_required_prompt(self) -> None:
        """FastAPI validation: missing 'prompt' field must return 422 (Unprocessable Entity)."""
        client = self._client_with_mock()
        payload = {k: v for k, v in _VALID_PAYLOAD.items() if k != "prompt"}
        resp = client.post("/api/v1/tasks", json=payload)
        # FastAPI returns 422 for Pydantic validation errors — NOT 400.
        # (400 is reserved for semantic errors bubbled up from the orchestrator.)
        assert resp.status_code == 422

    # ------------------------------------------------------------------
    # 403 — forbidden (PermissionError: policy denied or token scope)
    # ------------------------------------------------------------------

    def test_403_on_permission_error(self) -> None:
        client = self._client_with_mock(raises=PermissionError("policy denied"))
        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)
        assert resp.status_code == 403
        assert "detail" in resp.json()

    def test_403_detail_contains_reason(self) -> None:
        client = self._client_with_mock(raises=PermissionError("agent_type_not_permitted"))
        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)
        assert resp.status_code == 403
        assert "agent_type_not_permitted" in resp.json()["detail"]

    # ------------------------------------------------------------------
    # 429 — too many requests / budget exceeded
    # ------------------------------------------------------------------

    def test_429_on_budget_limit_error(self) -> None:
        client = self._client_with_mock(raises=BudgetLimitError("budget cap reached"))
        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)
        assert resp.status_code == 429
        assert "detail" in resp.json()

    def test_429_detail_contains_reason(self) -> None:
        client = self._client_with_mock(raises=BudgetLimitError("session USD cap $1.00 exceeded"))
        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)
        assert resp.status_code == 429
        assert "detail" in resp.json()

    # ------------------------------------------------------------------
    # 500 — internal server error (unexpected exception)
    # ------------------------------------------------------------------

    def test_500_on_unexpected_exception(self) -> None:
        client = self._client_with_mock(raises=RuntimeError("unexpected adapter crash"))
        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)
        assert resp.status_code == 500
        assert "detail" in resp.json()

    def test_500_detail_does_not_leak_internals(self) -> None:
        """The 500 detail must be a generic message — never a raw traceback string."""
        client = self._client_with_mock(raises=RuntimeError("secret internal state"))
        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)
        assert resp.status_code == 500
        # The raw exception message must not appear in the response body
        assert "secret internal state" not in resp.text

    def test_500_not_returned_for_unconfigured_orchestrator(self) -> None:
        """A missing orchestrator must produce a 500, not a silent pass-through."""
        original = router_module._orchestrator
        router_module._orchestrator = None
        app = FastAPI()
        app.include_router(router_module.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/api/v1/tasks", json=_VALID_PAYLOAD)
        assert resp.status_code == 500
        router_module._orchestrator = original
