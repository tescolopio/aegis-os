"""Timeout contract checks for the HITL approval endpoints and docs."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

import src.control_plane.router as router_module
from src.control_plane.approval_service import PendingApprovalConflictError
from src.control_plane.scheduler import ApprovalStatusSnapshot, PendingApprovalState
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager

REPO_ROOT = Path(__file__).parent.parent
API_REFERENCE_PATH = REPO_ROOT / "docs" / "api-reference.md"


class _TimedOutApprovalService:
    """Approval service double that simulates a timed-out workflow."""

    def __init__(self, task_id: str) -> None:
        self.get_snapshot = AsyncMock(
            return_value=ApprovalStatusSnapshot(
                task_id=task_id,
                session_id="session-a",
                agent_type="general",
                workflow_status=PendingApprovalState.TIMED_OUT.value,
                approval_state=PendingApprovalState.TIMED_OUT.value,
            )
        )
        self.approve = AsyncMock(
            side_effect=PendingApprovalConflictError(
                task_id=uuid4(),
                approval_state=PendingApprovalState.TIMED_OUT.value,
                workflow_status=PendingApprovalState.TIMED_OUT.value,
            )
        )
        self.deny = AsyncMock(side_effect=self.approve.side_effect)


def _issue_hitl_token(session_mgr: SessionManager) -> str:
    return session_mgr.issue_token(
        agent_type="general",
        requester_id="admin-user",
        session_id="session-a",
        allowed_actions=["hitl:approve", "hitl:deny"],
        role="admin",
    )


def test_hitl_timeout_behavior_is_documented() -> None:
    content = API_REFERENCE_PATH.read_text(encoding="utf-8")
    assert "returns `409` with error code `pending_approval_conflict`" in content


def test_hitl_timeout_returns_409() -> None:
    task_id = uuid4()
    service = _TimedOutApprovalService(str(task_id))
    service.approve.side_effect = PendingApprovalConflictError(
        task_id=task_id,
        approval_state=PendingApprovalState.TIMED_OUT.value,
        workflow_status=PendingApprovalState.TIMED_OUT.value,
    )
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="allow"))
    session_mgr = SessionManager()
    token = _issue_hitl_token(session_mgr)

    router_module.configure_hitl_controls(
        approval_service=service,
        policy_engine=policy_engine,
        session_mgr=session_mgr,
    )
    app = FastAPI()
    app.include_router(router_module.router, prefix="/api/v1")
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        f"/api/v1/tasks/{task_id}/approve",
        json={"approver_id": "admin-user", "reason": "Late approve"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 409
    assert response.json()["detail"]["error"]["code"] == "pending_approval_conflict"
