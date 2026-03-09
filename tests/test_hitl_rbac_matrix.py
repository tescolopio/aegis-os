"""Regression matrix for S2-2 admin-only HITL approval RBAC."""

from __future__ import annotations

import time
from collections.abc import Generator
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import src.control_plane.router as router_module
from src.control_plane.scheduler import ApprovalStatusSnapshot, PendingApprovalState
from src.governance.policy_engine.opa_client import PolicyEngine
from src.governance.session_mgr import SessionManager


class _MatrixApprovalService:
    """Pending snapshot plus no-op approve/deny handlers for RBAC matrix tests."""

    def __init__(self, task_id: str) -> None:
        self._snapshot = ApprovalStatusSnapshot(
            task_id=task_id,
            session_id="session-matrix",
            agent_type="general",
            workflow_status="human_intervention_required",
            approval_state=PendingApprovalState.AWAITING_APPROVAL.value,
        )

    async def get_pending_snapshot(self, _task_id: Any) -> ApprovalStatusSnapshot:
        return self._snapshot

    async def get_snapshot(self, _task_id: Any) -> ApprovalStatusSnapshot:
        return self._snapshot

    async def approve(self, task_id: Any, approver_id: str, reason: str) -> Any:
        return type(
            "Decision",
            (),
            {"status": "approved", "actor_id": approver_id, "reason": reason},
        )()

    async def deny(self, task_id: Any, approver_id: str, reason: str) -> Any:
        return type(
            "Decision",
            (),
            {"status": "denied", "actor_id": approver_id, "reason": reason},
        )()


@pytest.fixture(scope="session")
def live_opa_url() -> Generator[str, None, None]:
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


def _make_client(task_id: str, opa_url: str, session_mgr: SessionManager) -> TestClient:
    router_module.configure_hitl_controls(
        approval_service=_MatrixApprovalService(task_id),  # type: ignore[arg-type]
        policy_engine=PolicyEngine(opa_url=opa_url),
        session_mgr=session_mgr,
    )
    app = FastAPI()
    app.include_router(router_module.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False)


def _token_for_role(session_mgr: SessionManager, role: str | None) -> str:
    return session_mgr.issue_token(
        agent_type="general",
        requester_id="matrix-user",
        session_id="session-matrix",
        allowed_actions=["hitl:approve", "hitl:deny"],
        role=role,
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    ("endpoint", "role", "expected_status"),
    [
        ("approve", "admin", 200),
        ("approve", "operator", 403),
        ("approve", "viewer", 403),
        ("approve", "auditor", 403),
        ("approve", None, 403),
        ("deny", "admin", 200),
        ("deny", "operator", 403),
        ("deny", "viewer", 403),
        ("deny", "auditor", 403),
        ("deny", None, 403),
    ],
)
def test_hitl_rbac_matrix(
    live_opa_url: str,
    endpoint: str,
    role: str | None,
    expected_status: int,
) -> None:
    task_id = str(uuid4())
    session_mgr = SessionManager()
    client = _make_client(task_id, live_opa_url, session_mgr)
    token = _token_for_role(session_mgr, role)

    response = client.post(
        f"/api/v1/tasks/{task_id}/{endpoint}",
        json={"approver_id": "matrix-user", "reason": "matrix-check"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == expected_status, response.text
