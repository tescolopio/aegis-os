"""S2-1 tests for the PendingApproval Temporal workflow state."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

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

_TASK_QUEUE = "aegis-hitl-pending"


class _StubAdapter(BaseAdapter):
    """Adapter stub that records invocation count for execution-halt assertions."""

    def __init__(self, responses: list[LLMResponse] | None = None) -> None:
        self._responses = responses or [
            LLMResponse(
                content="approved-response",
                tokens_used=11,
                model="gpt-4o-mini",
                provider="openai",
                finish_reason="stop",
            )
        ]
        self.call_count = 0

    @property
    def provider_name(self) -> str:
        return "stub"

    async def complete(self, request: Any) -> LLMResponse:
        self.call_count += 1
        return self._responses[min(self.call_count - 1, len(self._responses) - 1)]


class _RecordingAuditLogger(AuditLogger):
    """Capture rendered audit entries after lifecycle_event expands metadata."""

    def __init__(self) -> None:
        super().__init__("test.hitl.pending-approval")
        self.entries: list[dict[str, Any]] = []

    def info(self, event: str, **kwargs: object) -> None:
        self.entries.append({"level": "info", "event": event, **kwargs})

    def warning(self, event: str, **kwargs: object) -> None:
        self.entries.append({"level": "warning", "event": event, **kwargs})

    def error(self, event: str, **kwargs: object) -> None:
        self.entries.append({"level": "error", "event": event, **kwargs})


def _make_input(*, projected_spend_usd: str = "75.25", timeout_seconds: int = 300) -> WorkflowInput:
    task_id = str(uuid.uuid4())
    return WorkflowInput(
        task_id=task_id,
        prompt="Summarise the flagged report.",
        agent_type="general",
        requester_id="workflow-user",
        session_id=f"session-{task_id}",
        projected_spend_usd=projected_spend_usd,
        approval_timeout_seconds=timeout_seconds,
    )


async def _start_pending_workflow(
    *,
    adapter: _StubAdapter | None = None,
    audit_logger: AuditLogger | None = None,
    workflow_input: WorkflowInput | None = None,
) -> tuple[Any, Any, _StubAdapter, AuditLogger, WorkflowInput, Any]:
    """Start a workflow and return environment, handle, adapter, audit logger, input."""
    wf_input = workflow_input or _make_input()
    stub_adapter = adapter or _StubAdapter()
    activity_audit = audit_logger or MagicMock(spec=AuditLogger)
    workflow_audit = WorkflowAuditActivities(audit_logger=activity_audit)
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=True, action="allow", reasons=[], fields=[])
    )
    activities = AegisActivities(
        adapter=stub_adapter,
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
    handle = await env.client.start_workflow(
        AgentTaskWorkflow.run,
        wf_input,
        id=wf_input.task_id,
        task_queue=_TASK_QUEUE,
    )
    return env, worker, stub_adapter, activity_audit, wf_input, handle


async def _wait_for_state(handle: Any, expected_state: str) -> ApprovalStatusSnapshot:
    """Poll the workflow query until the expected approval state is visible."""
    for _ in range(20):
        snapshot: ApprovalStatusSnapshot = await handle.query(AgentTaskWorkflow.approval_status)
        if snapshot.approval_state == expected_state:
            return snapshot
        await asyncio.sleep(0.05)
    return cast(ApprovalStatusSnapshot, await handle.query(AgentTaskWorkflow.approval_status))


@pytest.mark.integration
class TestPendingApprovalState:
    """S2-1 integration and unit coverage for the approval state machine."""

    @pytest.mark.asyncio
    async def test_transition_trigger_above_fifty_enters_pending_approval(self) -> None:
        env, worker, adapter, _audit, _wf_input, handle = await _start_pending_workflow()
        try:
            snapshot = await _wait_for_state(handle, PendingApprovalState.AWAITING_APPROVAL.value)
            assert snapshot.approval_state == PendingApprovalState.AWAITING_APPROVAL.value
            assert snapshot.workflow_status != "failed"
            assert adapter.call_count == 0
        finally:
            await worker.__aexit__(None, None, None)
            await env.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_exactly_fifty_does_not_remain_pending(self) -> None:
        wf_input = _make_input(projected_spend_usd="50.00")
        env, worker, adapter, _audit, _wf_input, handle = await _start_pending_workflow(
            workflow_input=wf_input
        )
        try:
            result: WorkflowOutput = await handle.result()
            assert result.workflow_status == "completed"
            assert result.approval_state == PendingApprovalState.NOT_REQUIRED.value
            assert adapter.call_count == 1
        finally:
            await worker.__aexit__(None, None, None)
            await env.__aexit__(None, None, None)

    def test_state_machine_enumerates_all_required_states(self) -> None:
        states = {state.value for state in PendingApprovalState}
        assert states == {
            "not-required",
            "awaiting-approval",
            "approved",
            "denied",
            "timed-out",
        }

    @pytest.mark.asyncio
    async def test_execution_halts_until_explicit_approve_signal(self) -> None:
        env, worker, adapter, _audit, _wf_input, handle = await _start_pending_workflow()
        try:
            snapshot = await _wait_for_state(handle, PendingApprovalState.AWAITING_APPROVAL.value)
            assert snapshot.approval_state == PendingApprovalState.AWAITING_APPROVAL.value
            assert adapter.call_count == 0

            await handle.signal(
                AgentTaskWorkflow.approve,
                ApprovalSignalPayload(
                    approver_id="admin-1",
                    reason="Budget extension approved",
                    approved=True,
                ),
            )
            result: WorkflowOutput = await handle.result()
            assert result.workflow_status == "completed"
            assert result.approval_state == PendingApprovalState.APPROVED.value
            assert adapter.call_count == 1
        finally:
            await worker.__aexit__(None, None, None)
            await env.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_approve_resumes_and_returns_task_response_shape(self) -> None:
        env, worker, _adapter, _audit, _wf_input, handle = await _start_pending_workflow()
        try:
            await _wait_for_state(handle, PendingApprovalState.AWAITING_APPROVAL.value)
            await handle.signal(
                AgentTaskWorkflow.approve,
                ApprovalSignalPayload(
                    approver_id="admin-2",
                    reason="Reviewed and approved",
                    approved=True,
                ),
            )
            result: WorkflowOutput = await handle.result()
            assert result.workflow_status == "completed"
            assert result.content == "approved-response"
            assert result.task_id
            assert result.model == "gpt-4o-mini"
        finally:
            await worker.__aexit__(None, None, None)
            await env.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_deny_terminates_with_denied_status_and_audit_event(self) -> None:
        audit = _RecordingAuditLogger()
        env, worker, _adapter, _audit, _wf_input, handle = await _start_pending_workflow(
            audit_logger=audit
        )
        try:
            await _wait_for_state(handle, PendingApprovalState.AWAITING_APPROVAL.value)
            await handle.signal(
                AgentTaskWorkflow.deny,
                ApprovalSignalPayload(
                    approver_id="admin-3",
                    reason="Denied due to overspend",
                    approved=False,
                ),
            )
            result: WorkflowOutput = await handle.result()
            assert result.workflow_status == PendingApprovalState.DENIED.value
            assert result.approval_state == PendingApprovalState.DENIED.value
            assert result.reason == "Denied due to overspend"
            deny_entries = [entry for entry in audit.entries if entry["event"] == "workflow.denied"]
            assert len(deny_entries) == 1
            assert deny_entries[0]["reason"] == "Denied due to overspend"
            assert deny_entries[0]["approver_id"] == "admin-3"
        finally:
            await worker.__aexit__(None, None, None)
            await env.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_pending_approval_timeout_auto_terminates(self) -> None:
        audit = _RecordingAuditLogger()
        env, worker, _adapter, _audit, _wf_input, handle = await _start_pending_workflow(
            audit_logger=audit,
            workflow_input=_make_input(timeout_seconds=2),
        )
        try:
            result: WorkflowOutput = await handle.result()
            assert result.workflow_status == PendingApprovalState.TIMED_OUT.value
            assert result.approval_state == PendingApprovalState.TIMED_OUT.value
            timeout_entries = [
                entry for entry in audit.entries if entry["event"] == "workflow.timed_out"
            ]
            assert len(timeout_entries) == 1
        finally:
            await worker.__aexit__(None, None, None)
            await env.__aexit__(None, None, None)
