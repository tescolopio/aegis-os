"""S2-2 and S2-4 tests for HITL approve/deny endpoints."""

from __future__ import annotations

import time
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from freezegun import freeze_time

import src.control_plane.router as router_module
from src.audit_vault.logger import AuditLogger
from src.control_plane.approval_service import (
    PendingApprovalConflictError,
    PendingApprovalNotFoundError,
)
from src.control_plane.scheduler import ApprovalStatusSnapshot, PendingApprovalState
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager


@dataclass
class _FakeApprovalService:
    """Small async test double for task approval signaling."""

    snapshot: ApprovalStatusSnapshot

    def __post_init__(self) -> None:
        self.approve = AsyncMock(
            return_value=type(
                "Decision",
                (),
                {
                    "status": PendingApprovalState.APPROVED.value,
                    "actor_id": "admin-user",
                },
            )()
        )
        self.deny = AsyncMock(
            return_value=type(
                "Decision",
                (),
                {
                    "status": PendingApprovalState.DENIED.value,
                    "actor_id": "admin-user",
                },
            )()
        )
        self.get_snapshot = AsyncMock(return_value=self.snapshot)
        self.get_pending_snapshot = AsyncMock(return_value=self.snapshot)


def _make_snapshot(task_id: UUID, session_id: str = "session-a") -> ApprovalStatusSnapshot:
    return ApprovalStatusSnapshot(
        task_id=str(task_id),
        session_id=session_id,
        agent_type="general",
        workflow_status="human_intervention_required",
        approval_state=PendingApprovalState.AWAITING_APPROVAL.value,
    )


def _make_app(
    *,
    approval_service: Any,
    policy_engine: PolicyEngine,
    session_mgr: SessionManager,
) -> TestClient:
    router_module.configure_hitl_controls(
        approval_service=approval_service,
        policy_engine=policy_engine,
        session_mgr=session_mgr,
    )
    app = FastAPI()
    app.include_router(router_module.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False)


def _issue_hitl_token(
    session_mgr: SessionManager,
    *,
    role: str | None = "admin",
    session_id: str = "session-a",
    expires_in_seconds: int | None = None,
) -> str:
    return session_mgr.issue_token(
        agent_type="general",
        requester_id="admin-user",
        session_id=session_id,
        allowed_actions=["hitl:approve", "hitl:deny"],
        role=role,
        expires_in_seconds=expires_in_seconds,
    )


class TestHitlEndpoints:
    """Unit coverage for S2-2 approval endpoints."""

    @pytest.fixture(autouse=True)
    def _restore_globals(self) -> Any:
        original_logger = router_module._logger
        original_service = router_module._approval_service
        original_policy = router_module._approval_policy_engine
        original_session_mgr = router_module._approval_session_mgr
        yield
        router_module._logger = original_logger
        router_module._approval_service = original_service
        router_module._approval_policy_engine = original_policy
        router_module._approval_session_mgr = original_session_mgr

    def test_admin_caller_approved_and_signal_sent(self) -> None:
        task_id = uuid4()
        service = _FakeApprovalService(_make_snapshot(task_id))
        policy_engine = MagicMock(spec=PolicyEngine)
        policy_engine.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="allow"))
        session_mgr = SessionManager()
        token = _issue_hitl_token(session_mgr)
        client = _make_app(
            approval_service=service,
            policy_engine=policy_engine,
            session_mgr=session_mgr,
        )

        response = client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user", "reason": "Looks good"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200, response.text
        service.approve.assert_awaited_once_with(task_id, "admin-user", "Looks good")
        assert policy_engine.evaluate.await_count == 1

    @pytest.mark.parametrize("path", ["approve", "deny"])
    def test_non_admin_caller_blocked_by_opa(self, path: str) -> None:
        task_id = uuid4()
        service = _FakeApprovalService(_make_snapshot(task_id))
        policy_engine = MagicMock(spec=PolicyEngine)
        policy_engine.evaluate = AsyncMock(
            return_value=PolicyResult(allowed=False, action="reject", reasons=["rbac_denied"])
        )
        session_mgr = SessionManager()
        token = _issue_hitl_token(session_mgr, role="operator")
        client = _make_app(
            approval_service=service,
            policy_engine=policy_engine,
            session_mgr=session_mgr,
        )

        response = client.post(
            f"/api/v1/tasks/{task_id}/{path}",
            json={"approver_id": "operator-user", "reason": "Nope"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert policy_engine.evaluate.await_count == 1
        assert service.approve.await_count == 0
        assert service.deny.await_count == 0

    def test_invalid_token_blocked(self) -> None:
        task_id = uuid4()
        service = _FakeApprovalService(_make_snapshot(task_id))
        client = _make_app(
            approval_service=service,
            policy_engine=MagicMock(spec=PolicyEngine),
            session_mgr=SessionManager(),
        )

        response = client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user", "reason": "Looks good"},
            headers={"Authorization": "Bearer invalid.token.value"},
        )

        assert response.status_code == 401

    def test_invalid_body_returns_400(self) -> None:
        task_id = uuid4()
        service = _FakeApprovalService(_make_snapshot(task_id))
        policy_engine = MagicMock(spec=PolicyEngine)
        policy_engine.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="allow"))
        session_mgr = SessionManager()
        token = _issue_hitl_token(session_mgr)
        client = _make_app(
            approval_service=service,
            policy_engine=policy_engine,
            session_mgr=session_mgr,
        )

        response = client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 400
        body = response.json()
        assert body["detail"]["error"]["code"] == "invalid_request"

    def test_nonexistent_task_returns_structured_404(self) -> None:
        task_id = uuid4()
        service = _FakeApprovalService(_make_snapshot(task_id))
        service.get_snapshot.side_effect = PendingApprovalNotFoundError(
            f"No active PendingApproval workflow found for task_id={task_id}"
        )
        policy_engine = MagicMock(spec=PolicyEngine)
        policy_engine.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="allow"))
        session_mgr = SessionManager()
        token = _issue_hitl_token(session_mgr)
        client = _make_app(
            approval_service=service,
            policy_engine=policy_engine,
            session_mgr=session_mgr,
        )

        response = client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user", "reason": "Looks good"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 404
        body = response.json()
        assert body["detail"]["error"]["code"] == "pending_approval_not_found"
        assert body["detail"]["error"]["task_id"] == str(task_id)

    def test_timed_out_task_returns_structured_409(self) -> None:
        task_id = uuid4()
        service = _FakeApprovalService(_make_snapshot(task_id))
        service.approve.side_effect = PendingApprovalConflictError(
            task_id=task_id,
            approval_state=PendingApprovalState.TIMED_OUT.value,
            workflow_status=PendingApprovalState.TIMED_OUT.value,
        )
        policy_engine = MagicMock(spec=PolicyEngine)
        policy_engine.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="allow"))
        session_mgr = SessionManager()
        token = _issue_hitl_token(session_mgr)
        client = _make_app(
            approval_service=service,
            policy_engine=policy_engine,
            session_mgr=session_mgr,
        )

        response = client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user", "reason": "Late approve"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 409
        body = response.json()
        assert body["detail"]["error"]["code"] == "pending_approval_conflict"
        assert body["detail"]["error"]["task_id"] == str(task_id)


class TestAdversarialApproval:
    """Unit and integration coverage for S2-4 adversarial approval handling."""

    @pytest.fixture(autouse=True)
    def _restore_globals(self) -> Any:
        original_logger = router_module._logger
        original_service = router_module._approval_service
        original_policy = router_module._approval_policy_engine
        original_session_mgr = router_module._approval_session_mgr
        yield
        router_module._logger = original_logger
        router_module._approval_service = original_service
        router_module._approval_policy_engine = original_policy
        router_module._approval_session_mgr = original_session_mgr

    @pytest.fixture(scope="session")
    def live_opa_url(self) -> Generator[str, None, None]:
        try:
            from testcontainers.core.container import DockerContainer
        except ImportError:
            pytest.skip("testcontainers not installed; skipping live OPA tests")

        policy_path = Path(__file__).parent.parent / "policies" / "agent_access.rego"
        container = DockerContainer("openpolicyagent/opa:0.68.0")
        container.with_command("run --server --addr :8181")
        container.with_exposed_ports(8181)
        try:
            container.start()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"Docker unavailable – skipping live OPA tests: {exc}")

        port = container.get_exposed_port(8181)
        url = f"http://localhost:{port}"
        deadline = time.monotonic() + 30.0
        with httpx.Client(timeout=2.0) as client:
            while time.monotonic() < deadline:
                try:
                    health = client.get(f"{url}/health")
                except httpx.HTTPError:
                    time.sleep(0.5)
                    continue
                if health.status_code == 200:
                    break
                time.sleep(0.5)
            else:
                container.stop()
                pytest.skip("OPA container did not become ready in time; skipping")

        with httpx.Client(timeout=10.0) as client:
            response = client.put(
                f"{url}/v1/policies/aegis/agent_access",
                content=policy_path.read_text(),
                headers={"Content-Type": "text/plain"},
            )
            response.raise_for_status()

        yield url
        container.stop()

    def test_expired_token_on_approve_returns_401_and_audit_event(self) -> None:
        task_id = uuid4()
        logger = MagicMock(spec=AuditLogger)
        router_module._logger = logger
        service = _FakeApprovalService(_make_snapshot(task_id))
        session_mgr = SessionManager()
        policy_engine = MagicMock(spec=PolicyEngine)
        policy_engine.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="allow"))
        client = _make_app(
            approval_service=service,
            policy_engine=policy_engine,
            session_mgr=session_mgr,
        )

        with freeze_time("2026-03-06T12:00:00Z"):
            token = _issue_hitl_token(session_mgr, expires_in_seconds=1)
        with freeze_time("2026-03-06T12:00:02Z"):
            response = client.post(
                f"/api/v1/tasks/{task_id}/approve",
                json={"approver_id": "admin-user", "reason": "Looks good"},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert response.status_code == 401
        logger.warning.assert_any_call("jit.expired", task_id=str(task_id), action="approve")

    def test_revoked_token_returns_401_within_one_second(self) -> None:
        task_id = uuid4()
        logger = MagicMock(spec=AuditLogger)
        router_module._logger = logger
        service = _FakeApprovalService(_make_snapshot(task_id))
        session_mgr = SessionManager()
        policy_engine = MagicMock(spec=PolicyEngine)
        policy_engine.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="allow"))
        token = _issue_hitl_token(session_mgr)
        session_mgr.revoke_token(token)
        client = _make_app(
            approval_service=service,
            policy_engine=policy_engine,
            session_mgr=session_mgr,
        )

        response = client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user", "reason": "Looks good"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 401
        logger.warning.assert_any_call("jit.revoked", task_id=str(task_id), action="approve")

    def test_wrong_session_token_returns_403_and_audit_event(self) -> None:
        task_id = uuid4()
        logger = MagicMock(spec=AuditLogger)
        router_module._logger = logger
        service = _FakeApprovalService(_make_snapshot(task_id, session_id="session-b"))
        session_mgr = SessionManager()
        policy_engine = MagicMock(spec=PolicyEngine)
        policy_engine.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="allow"))
        token = _issue_hitl_token(session_mgr, session_id="session-a")
        client = _make_app(
            approval_service=service,
            policy_engine=policy_engine,
            session_mgr=session_mgr,
        )

        response = client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user", "reason": "Looks good"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        logger.warning.assert_any_call(
            "audit.cross_session_attempt",
            task_id=str(task_id),
            action="approve",
            token_session_id="session-a",
            workflow_session_id="session-b",
        )

    def test_adversarial_no_silent_accept(self, live_opa_url: str) -> None:
        task_id = uuid4()
        logger = MagicMock(spec=AuditLogger)
        router_module._logger = logger
        service = _FakeApprovalService(_make_snapshot(task_id))
        session_mgr = SessionManager()
        client = _make_app(
            approval_service=service,
            policy_engine=PolicyEngine(opa_url=live_opa_url),
            session_mgr=session_mgr,
        )

        valid_admin = _issue_hitl_token(session_mgr)
        revoked = _issue_hitl_token(session_mgr)
        session_mgr.revoke_token(revoked)
        wrong_role = _issue_hitl_token(session_mgr, role="operator")
        wrong_session = _issue_hitl_token(session_mgr, session_id="other-session")
        malformed = f"{valid_admin}broken"
        with freeze_time("2026-03-06T12:00:00Z"):
            expiring = _issue_hitl_token(session_mgr, expires_in_seconds=1)
        with freeze_time("2026-03-06T12:00:02Z"):
            expired_response = client.post(
                f"/api/v1/tasks/{task_id}/approve",
                json={"approver_id": "admin-user", "reason": "approve"},
                headers={"Authorization": f"Bearer {expiring}"},
            )

        scenarios = {
            "expired": expired_response,
            "revoked": client.post(
                f"/api/v1/tasks/{task_id}/approve",
                json={"approver_id": "admin-user", "reason": "approve"},
                headers={"Authorization": f"Bearer {revoked}"},
            ),
            "wrong_session": client.post(
                f"/api/v1/tasks/{task_id}/approve",
                json={"approver_id": "admin-user", "reason": "approve"},
                headers={"Authorization": f"Bearer {wrong_session}"},
            ),
            "wrong_role": client.post(
                f"/api/v1/tasks/{task_id}/approve",
                json={"approver_id": "operator-user", "reason": "approve"},
                headers={"Authorization": f"Bearer {wrong_role}"},
            ),
            "malformed_signature": client.post(
                f"/api/v1/tasks/{task_id}/approve",
                json={"approver_id": "admin-user", "reason": "approve"},
                headers={"Authorization": f"Bearer {malformed}"},
            ),
        }

        for response in scenarios.values():
            assert 400 <= response.status_code < 500

        logged_events = {call.args[0] for call in logger.warning.call_args_list if call.args}
        assert {
            "jit.expired",
            "jit.revoked",
            "audit.cross_session_attempt",
            "hitl.rbac_denied",
            "jit.invalid",
        }.issubset(logged_events)
