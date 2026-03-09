"""Completeness checks for the live HITL API reference contract."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

import src.control_plane.router as router_module
from src.control_plane.approval_service import PendingApprovalNotFoundError
from src.control_plane.scheduler import ApprovalStatusSnapshot, PendingApprovalState
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager

REPO_ROOT = Path(__file__).parent.parent
API_REFERENCE_PATH = REPO_ROOT / "docs" / "api-reference.md"


@dataclass
class _FakeApprovalService:
    snapshot: ApprovalStatusSnapshot

    def __post_init__(self) -> None:
        self.approve = AsyncMock(
            return_value=type(
                "Decision",
                (),
                {"status": PendingApprovalState.APPROVED.value, "actor_id": "admin-user"},
            )()
        )
        self.deny = AsyncMock(
            return_value=type(
                "Decision",
                (),
                {"status": PendingApprovalState.DENIED.value, "actor_id": "admin-user"},
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


def _issue_hitl_token(session_mgr: SessionManager, *, role: str | None = "admin") -> str:
    return session_mgr.issue_token(
        agent_type="general",
        requester_id="admin-user",
        session_id="session-a",
        allowed_actions=["hitl:approve", "hitl:deny"],
        role=role,
    )


def test_api_reference_documents_live_task_based_hitl_endpoints() -> None:
    content = API_REFERENCE_PATH.read_text(encoding="utf-8")
    assert "/api/v1/tasks/{task_id}/approve" in content
    assert "/api/v1/tasks/{task_id}/deny" in content
    assert "/api/v1/workflows/{workflow_id}/approve" not in content
    assert "/api/v1/workflows/{workflow_id}/deny" not in content


def test_api_reference_documents_live_status_codes() -> None:
    task_id = uuid4()
    service = _FakeApprovalService(_make_snapshot(task_id))
    allow_policy = MagicMock(spec=PolicyEngine)
    allow_policy.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=True, action="allow")
    )
    deny_policy = MagicMock(spec=PolicyEngine)
    deny_policy.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=False, action="reject", reasons=["rbac_denied"])
    )

    session_mgr = SessionManager()
    valid_token = _issue_hitl_token(session_mgr)

    allow_client = _make_app(
        approval_service=service,
        policy_engine=allow_policy,
        session_mgr=session_mgr,
    )
    deny_client = _make_app(
        approval_service=service,
        policy_engine=deny_policy,
        session_mgr=session_mgr,
    )

    not_found_service = _FakeApprovalService(_make_snapshot(task_id))
    not_found_service.get_snapshot.side_effect = PendingApprovalNotFoundError(
        f"No active PendingApproval workflow found for task_id={task_id}"
    )
    not_found_client = _make_app(
        approval_service=not_found_service,
        policy_engine=allow_policy,
        session_mgr=session_mgr,
    )

    live_statuses = {
        allow_client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user", "reason": "Approved"},
            headers={"Authorization": f"Bearer {valid_token}"},
        ).status_code,
        allow_client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user"},
            headers={"Authorization": f"Bearer {valid_token}"},
        ).status_code,
        allow_client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user", "reason": "Approved"},
            headers={"Authorization": "Bearer invalid.token"},
        ).status_code,
        deny_client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user", "reason": "Approved"},
            headers={"Authorization": f"Bearer {valid_token}"},
        ).status_code,
        not_found_client.post(
            f"/api/v1/tasks/{task_id}/approve",
            json={"approver_id": "admin-user", "reason": "Approved"},
            headers={"Authorization": f"Bearer {valid_token}"},
        ).status_code,
    }

    content = API_REFERENCE_PATH.read_text(encoding="utf-8")
    documented_codes = {
        int(code)
        for code in ["200", "400", "401", "403", "404", "409"]
        if f"`{code}`" in content
    }
    assert live_statuses <= documented_codes, (
        "API reference is missing live HITL status codes. "
        f"live={sorted(live_statuses)} documented={sorted(documented_codes)}"
    )
