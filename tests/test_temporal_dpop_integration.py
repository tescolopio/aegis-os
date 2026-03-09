"""Temporal integration test for protected outbound adapter flow."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.adapters.base import (
    AdapterSecurityError,
    BaseAdapter,
    LLMRequest,
    LLMResponse,
    require_sender_constrained_request,
)
from src.audit_vault.logger import AuditLogger
from src.control_plane.scheduler import (
    AegisActivities,
    AgentTaskWorkflow,
    WorkflowInput,
    WorkflowOutput,
)
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import DPoPReplayError, SessionManager

_TASK_QUEUE = "aegis-temporal-dpop"


class _EnforcingAdapter(BaseAdapter):
    def __init__(self, session_mgr: SessionManager, audit: AuditLogger) -> None:
        self._session_mgr = session_mgr
        self._audit = audit
        self.calls: list[LLMRequest] = []

    @property
    def provider_name(self) -> str:
        return "enforcing-adapter"

    def outbound_request_binding(self, request: LLMRequest) -> tuple[str, str] | None:
        return ("POST", "https://provider.example.test/v1/complete")

    async def complete(self, request: LLMRequest) -> LLMResponse:
        try:
            claims = require_sender_constrained_request(
                request,
                session_mgr=self._session_mgr,
                http_method="POST",
                http_url="https://provider.example.test/v1/complete",
            )
        except AdapterSecurityError as exc:
            event_name = "dpop.proof.rejected"
            outcome = "deny"
            if isinstance(exc.__cause__, DPoPReplayError):
                event_name = "dpop.proof.replayed"
                outcome = "error"
            self._audit.stage_event(
                event_name,
                outcome=outcome,
                stage="llm-invoke",
                task_id=request.metadata.get("task_id", "unknown"),
                agent_type=request.metadata.get("agent_type", "unknown"),
                provider=self.provider_name,
                reason=str(exc),
            )
            raise

        self.calls.append(request)
        if claims is not None:
            self._audit.stage_event(
                "dpop.proof.validated",
                outcome="allow",
                stage="llm-invoke",
                task_id=claims.task_id or "unknown",
                agent_type=claims.agent_type,
                provider=self.provider_name,
                jti=claims.jti,
            )
        return LLMResponse(
            content="temporal-dpop-ok",
            tokens_used=13,
            model=request.model,
            provider=self.provider_name,
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_agent_task_workflow_protected_outbound_flow_survives_temporal_execution() -> None:
    session_mgr = SessionManager()
    audit = MagicMock(spec=AuditLogger)
    adapter = _EnforcingAdapter(session_mgr=session_mgr, audit=audit)
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=True, action="allow", reasons=[], fields=[])
    )
    activities = AegisActivities(
        adapter=adapter,
        session_mgr=session_mgr,
        audit_logger=audit,
        policy_engine=policy_engine,
    )
    inp = WorkflowInput(
        task_id=str(uuid.uuid4()),
        prompt="Temporal protected outbound flow",
        agent_type="general",
        requester_id="temporal-user",
        protect_outbound_request=True,
    )

    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=_TASK_QUEUE,
            workflows=[AgentTaskWorkflow],
            activities=[
                activities.pre_pii_scrub,
                activities.policy_eval,
                activities.jit_token_issue,
                activities.llm_invoke,
                activities.post_sanitize,
            ],
        ):
            result: WorkflowOutput = await env.client.execute_workflow(
                AgentTaskWorkflow.run,
                inp,
                id=inp.task_id,
                task_queue=_TASK_QUEUE,
            )

    assert result.workflow_status == "completed"
    assert result.content == "temporal-dpop-ok"
    assert len(adapter.calls) == 1
    metadata = adapter.calls[0].metadata
    assert metadata["aegis_protected"] == "true"
    assert "aegis_dpop_proof" in metadata
    token_claims = session_mgr.validate_token(metadata["aegis_token"])
    assert token_claims.cnf is not None

    stage_events = [call.args[0] for call in audit.stage_event.call_args_list]
    assert "token.sender_constrained_issued" in stage_events
    assert "dpop.proof.validated" in stage_events


@pytest.mark.integration
@pytest.mark.asyncio
async def test_agent_task_workflow_rejects_replayed_temporal_dpop_proof() -> None:
    session_mgr = SessionManager()
    audit = MagicMock(spec=AuditLogger)
    adapter = _EnforcingAdapter(session_mgr=session_mgr, audit=audit)
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=True, action="allow", reasons=[], fields=[])
    )
    activities = AegisActivities(
        adapter=adapter,
        session_mgr=session_mgr,
        audit_logger=audit,
        policy_engine=policy_engine,
    )
    inp = WorkflowInput(
        task_id=str(uuid.uuid4()),
        prompt="Temporal replay rejection flow",
        agent_type="general",
        requester_id="temporal-user",
        protect_outbound_request=True,
    )

    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=_TASK_QUEUE,
            workflows=[AgentTaskWorkflow],
            activities=[
                activities.pre_pii_scrub,
                activities.policy_eval,
                activities.jit_token_issue,
                activities.llm_invoke,
                activities.post_sanitize,
            ],
        ):
            result: WorkflowOutput = await env.client.execute_workflow(
                AgentTaskWorkflow.run,
                inp,
                id=inp.task_id,
                task_queue=_TASK_QUEUE,
            )

    assert result.workflow_status == "completed"
    assert len(adapter.calls) == 1

    with pytest.raises(AdapterSecurityError):
        await adapter.complete(adapter.calls[0])

    replay_calls = [
        call for call in audit.stage_event.call_args_list if call.args[0] == "dpop.proof.replayed"
    ]
    assert replay_calls, "Expected dpop.proof.replayed audit event on replayed Temporal proof"
