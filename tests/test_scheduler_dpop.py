"""Tests for protected outbound DPoP flow inside Temporal activities."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from temporalio import activity

from src.adapters.base import BaseAdapter, LLMRequest, LLMResponse
from src.audit_vault.logger import AuditLogger
from src.control_plane.scheduler import AegisActivities, LLMInvokeInput
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager


class _CaptureAdapter(BaseAdapter):
    def __init__(self) -> None:
        self.calls: list[LLMRequest] = []

    @property
    def provider_name(self) -> str:
        return "capture"

    def outbound_request_binding(self, request: LLMRequest) -> tuple[str, str] | None:
        return ("POST", "https://capture.example.test/complete")

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        return LLMResponse(
            content="ok",
            tokens_used=9,
            model=request.model,
            provider=self.provider_name,
        )


@pytest.mark.asyncio
async def test_llm_invoke_issues_sender_constrained_adapter_token_when_protected() -> None:
    adapter = _CaptureAdapter()
    audit = MagicMock(spec=AuditLogger)
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="allow"))
    session_mgr = SessionManager()
    protected_private_key_pem, protected_public_jwk = session_mgr.generate_dpop_key_pair()
    activities = AegisActivities(
        adapter=adapter,
        policy_engine=policy_engine,
        session_mgr=session_mgr,
        audit_logger=audit,
    )
    base_token = session_mgr.issue_token(agent_type="general", requester_id="user-scheduler")

    activity_info = MagicMock()
    activity_info.attempt = 1
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(activity, "info", lambda: activity_info)
        result = await activities.llm_invoke(
            LLMInvokeInput(
                task_id="task-scheduler-1",
                token=base_token,
                sanitized_prompt="Protected scheduler test",
                agent_type="general",
                requester_id="user-scheduler",
                model="gpt-4o-mini",
                max_tokens=100,
                temperature=0.2,
                system_prompt="",
                protect_outbound_request=True,
                rotation_key="llm:task-scheduler-1",
                protected_private_key_pem=protected_private_key_pem,
                protected_public_jwk=protected_public_jwk,
            )
        )

    assert result.content == "ok"
    assert len(adapter.calls) == 1
    metadata = adapter.calls[0].metadata
    assert metadata["aegis_protected"] == "true"
    assert "aegis_dpop_proof" in metadata
    claims = session_mgr.validate_token(metadata["aegis_token"])
    assert claims.cnf is not None
    stage_events = [call.args[0] for call in audit.stage_event.call_args_list]
    assert "token.sender_constrained_issued" in stage_events
