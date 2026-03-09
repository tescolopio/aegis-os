"""Tests for sender-constrained orchestrator and adapter flows."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.adapters.base import AdapterSecurityError, BaseAdapter, LLMRequest, LLMResponse
from src.adapters.openai_adapter import OpenAIAdapter
from src.audit_vault.logger import AuditLogger
from src.control_plane.orchestrator import Orchestrator, OrchestratorRequest
from src.governance.guardrails import Guardrails
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager


class _CaptureAdapter(BaseAdapter):
    def __init__(self) -> None:
        self.requests: list[LLMRequest] = []

    @property
    def provider_name(self) -> str:
        return "capture"

    def outbound_request_binding(self, request: LLMRequest) -> tuple[str, str] | None:
        return ("POST", "https://capture.example.test/complete")

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        return LLMResponse(
            content="ok",
            tokens_used=5,
            model=request.model,
            provider="capture",
        )


def _make_policy_engine() -> PolicyEngine:
    pe = MagicMock(spec=PolicyEngine)
    pe.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="allow"))
    return pe


def _make_orchestrator(
    *,
    adapter: BaseAdapter,
    session_mgr: SessionManager | None = None,
) -> Orchestrator:
    return Orchestrator(
        adapter=adapter,
        guardrails=Guardrails(),
        policy_engine=_make_policy_engine(),
        session_mgr=session_mgr or SessionManager(),
        audit_logger=MagicMock(spec=AuditLogger),
    )


@pytest.mark.asyncio
async def test_orchestrator_issues_sender_constrained_adapter_token_for_protected_flows() -> None:
    adapter = _CaptureAdapter()
    session_mgr = SessionManager()
    orchestrator = _make_orchestrator(adapter=adapter, session_mgr=session_mgr)

    result = await orchestrator.run(
        OrchestratorRequest(
            prompt="Protected outbound test",
            agent_type="general",
            requester_id="user-dpop",
            model="stub",
            protect_outbound_request=True,
        )
    )

    assert result.session_token
    assert len(adapter.requests) == 1
    metadata = adapter.requests[0].metadata
    assert metadata["aegis_protected"] == "true"
    assert "aegis_dpop_proof" in metadata
    claims = session_mgr.validate_token(metadata["aegis_token"])
    assert claims.cnf is not None
    assert claims.task_id == str(result.task_id)


@pytest.mark.asyncio
async def test_openai_adapter_rejects_missing_proof_for_protected_request() -> None:
    adapter = OpenAIAdapter(api_key="test-key", session_mgr=SessionManager())
    request = LLMRequest(
        prompt="hello",
        model="gpt-4o-mini",
        metadata={
            "aegis_token": "token-only",
            "aegis_protected": "true",
        },
    )

    with pytest.raises(AdapterSecurityError, match="aegis_dpop_proof"):
        await adapter.complete(request)


@pytest.mark.asyncio
async def test_openai_adapter_accepts_matching_sender_constrained_request() -> None:
    session_mgr = SessionManager()
    audit = MagicMock(spec=AuditLogger)
    adapter = OpenAIAdapter(api_key="test-key", session_mgr=session_mgr, audit_logger=audit)
    private_key_pem, public_jwk = session_mgr.generate_dpop_key_pair()
    token = session_mgr.issue_sender_constrained_token(
        agent_type="general",
        requester_id="user-dpop",
        public_jwk=public_jwk,
        task_id="task-openai-1",
        allowed_actions=["llm.invoke"],
    )
    proof = session_mgr.issue_dpop_proof(
        private_key_pem,
        public_jwk,
        http_method="POST",
        http_url="https://api.openai.com/v1/chat/completions",
        access_token=token,
    )
    request = LLMRequest(
        prompt="hello",
        model="gpt-4o-mini",
        metadata={
            "aegis_token": token,
            "aegis_dpop_proof": proof,
            "aegis_protected": "true",
        },
    )

    response_mock = MagicMock()
    response_mock.raise_for_status.return_value = None
    response_mock.json.return_value = {
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        "usage": {"total_tokens": 7},
    }

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=response_mock)) as post_mock:
        response = await adapter.complete(request)

    assert response.content == "ok"
    assert post_mock.await_count == 1
    stage_events = [call.args[0] for call in audit.stage_event.call_args_list]
    assert "dpop.proof.validated" in stage_events


@pytest.mark.asyncio
async def test_openai_adapter_emits_replay_audit_event() -> None:
    session_mgr = SessionManager()
    audit = MagicMock(spec=AuditLogger)
    adapter = OpenAIAdapter(api_key="test-key", session_mgr=session_mgr, audit_logger=audit)
    private_key_pem, public_jwk = session_mgr.generate_dpop_key_pair()
    token = session_mgr.issue_sender_constrained_token(
        agent_type="general",
        requester_id="user-dpop",
        public_jwk=public_jwk,
        task_id="task-openai-2",
        allowed_actions=["llm.invoke"],
    )
    proof = session_mgr.issue_dpop_proof(
        private_key_pem,
        public_jwk,
        http_method="POST",
        http_url="https://api.openai.com/v1/chat/completions",
        access_token=token,
        proof_jti="proof-replay-1",
    )
    request = LLMRequest(
        prompt="hello",
        model="gpt-4o-mini",
        metadata={
            "aegis_token": token,
            "aegis_dpop_proof": proof,
            "aegis_protected": "true",
        },
    )
    response_mock = MagicMock()
    response_mock.raise_for_status.return_value = None
    response_mock.json.return_value = {
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        "usage": {"total_tokens": 7},
    }

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=response_mock)):
        await adapter.complete(request)

    with pytest.raises(AdapterSecurityError):
        await adapter.complete(request)

    replay_calls = [
        call for call in audit.stage_event.call_args_list if call.args[0] == "dpop.proof.replayed"
    ]
    assert replay_calls, "Expected dpop.proof.replayed audit event on proof replay"
