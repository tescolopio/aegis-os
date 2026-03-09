"""W2-3 integration checks for PendingApproval metrics exported by the API."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from prometheus_client import REGISTRY
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

import src.main as main_module
from src.adapters.base import BaseAdapter, LLMResponse
from src.audit_vault.logger import AuditLogger
from src.control_plane.scheduler import (
    AegisActivities,
    AgentTaskWorkflow,
    ApprovalSignalPayload,
    ApprovalStatusSnapshot,
    PendingApprovalState,
    WorkflowAuditActivities,
    WorkflowInput,
    WorkflowOutput,
)
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult

_TASK_QUEUE = "aegis-hitl-pending-metrics"


class _StubAdapter(BaseAdapter):
    """Adapter stub used to verify execution remains paused until approval."""

    def __init__(self) -> None:
        self.call_count = 0

    @property
    def provider_name(self) -> str:
        return "stub"

    async def complete(self, request: Any) -> LLMResponse:
        self.call_count += 1
        return LLMResponse(
            content="approved-response",
            tokens_used=11,
            model="gpt-4o-mini",
            provider="openai",
            finish_reason="stop",
        )


class _HandleBackedApprovalService:
    """Minimal approval service double for environments without workflow listing RPCs."""

    def __init__(self, handle: Any) -> None:
        self._handle = handle

    async def list_pending_snapshots(
        self,
        *,
        limit: int = 200,
    ) -> list[ApprovalStatusSnapshot]:
        del limit
        snapshot = cast(
            ApprovalStatusSnapshot,
            await self._handle.query(AgentTaskWorkflow.approval_status),
        )
        if snapshot.approval_state == PendingApprovalState.AWAITING_APPROVAL.value:
            return [snapshot]
        return []


def _sample_pending_metric(task_id: str) -> float | None:
    value = REGISTRY.get_sample_value(
        "aegis_workflow_pending_approval_seconds",
        {"workflow_id": task_id},
    )
    return float(value) if value is not None else None


def _make_input(*, projected_spend_usd: str = "75.25") -> WorkflowInput:
    task_id = str(uuid.uuid4())
    return WorkflowInput(
        task_id=task_id,
        prompt="Summarise the flagged report.",
        agent_type="general",
        requester_id="workflow-user",
        session_id=f"session-{task_id}",
        projected_spend_usd=projected_spend_usd,
        approval_timeout_seconds=300,
    )


async def _wait_for_state(handle: Any, expected_state: str) -> ApprovalStatusSnapshot:
    for _ in range(20):
        snapshot: ApprovalStatusSnapshot = await handle.query(AgentTaskWorkflow.approval_status)
        if snapshot.approval_state == expected_state:
            return snapshot
        await asyncio.sleep(0.05)
    return cast(ApprovalStatusSnapshot, await handle.query(AgentTaskWorkflow.approval_status))


@pytest.mark.asyncio
async def test_pending_snapshot_exposes_pending_since_timestamp() -> None:
    adapter = _StubAdapter()
    activity_audit = MagicMock(spec=AuditLogger)
    workflow_audit = WorkflowAuditActivities(audit_logger=activity_audit)
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=True, action="allow", reasons=[], fields=[])
    )
    activities = AegisActivities(
        adapter=adapter,
        audit_logger=activity_audit,
        policy_engine=policy_engine,
    )

    env = await WorkflowEnvironment.start_time_skipping()
    worker = Worker(
        env.client,
        task_queue=_TASK_QUEUE,
        workflows=[AgentTaskWorkflow],
        activities=[
            activities.pre_pii_scrub,
            activities.policy_eval,
            activities.jit_token_issue,
            activities.llm_invoke,
            activities.post_sanitize,
            workflow_audit.record_event,
        ],
    )
    await worker.__aenter__()

    try:
        wf_input = _make_input()
        handle = await env.client.start_workflow(
            AgentTaskWorkflow.run,
            wf_input,
            id=wf_input.task_id,
            task_queue=_TASK_QUEUE,
        )
        snapshot = await _wait_for_state(handle, PendingApprovalState.AWAITING_APPROVAL.value)
        assert snapshot.pending_since_epoch_seconds is not None
        assert snapshot.pending_since_epoch_seconds > 0
    finally:
        await worker.__aexit__(None, None, None)
        await env.__aexit__(None, None, None)


@pytest.mark.asyncio
async def test_pending_approval_metric_refresh_tracks_and_clears_real_workflow() -> None:
    adapter = _StubAdapter()
    activity_audit = MagicMock(spec=AuditLogger)
    workflow_audit = WorkflowAuditActivities(audit_logger=activity_audit)
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=True, action="allow", reasons=[], fields=[])
    )
    activities = AegisActivities(
        adapter=adapter,
        audit_logger=activity_audit,
        policy_engine=policy_engine,
    )

    env = await WorkflowEnvironment.start_time_skipping()
    worker = Worker(
        env.client,
        task_queue=_TASK_QUEUE,
        workflows=[AgentTaskWorkflow],
        activities=[
            activities.pre_pii_scrub,
            activities.policy_eval,
            activities.jit_token_issue,
            activities.llm_invoke,
            activities.post_sanitize,
            workflow_audit.record_event,
        ],
    )
    await worker.__aenter__()

    try:
        wf_input = _make_input()
        handle = await env.client.start_workflow(
            AgentTaskWorkflow.run,
            wf_input,
            id=wf_input.task_id,
            task_queue=_TASK_QUEUE,
        )
        snapshot = await _wait_for_state(handle, PendingApprovalState.AWAITING_APPROVAL.value)
        assert snapshot.pending_since_epoch_seconds is not None
        pending_since = snapshot.pending_since_epoch_seconds

        service = _HandleBackedApprovalService(handle)
        await main_module.refresh_pending_approval_metrics(
            service,
            now_fn=lambda: pending_since + 86405.0,
        )
        metric_value = _sample_pending_metric(wf_input.task_id)
        assert metric_value == pytest.approx(86405.0)

        await handle.signal(
            AgentTaskWorkflow.approve,
            ApprovalSignalPayload(
                approver_id="admin-1",
                reason="Budget extension approved",
                approved=True,
            ),
        )
        result: WorkflowOutput = await handle.result()
        assert result.approval_state == PendingApprovalState.APPROVED.value

        await main_module.refresh_pending_approval_metrics(service)
        assert _sample_pending_metric(wf_input.task_id) is None
    finally:
        await main_module.refresh_pending_approval_metrics(None)
        await worker.__aexit__(None, None, None)
        await env.__aexit__(None, None, None)
