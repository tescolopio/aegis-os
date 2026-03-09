"""S2-3 tests for JIT token re-issue on Temporal activity retries."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from freezegun import freeze_time
from jose import jwt
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.adapters.base import BaseAdapter, LLMRequest, LLMResponse
from src.audit_vault.logger import AuditLogger
from src.control_plane.scheduler import (
    AegisActivities,
    AgentTaskWorkflow,
    WorkflowAuditActivities,
    WorkflowInput,
    WorkflowOutput,
)
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import DPoPProofError, SessionManager, TokenRevokedError

_TASK_QUEUE = "aegis-jit-rotation"


class _RetryAdapter(BaseAdapter):
    """Adapter that records presented tokens and fails a configurable number of times."""

    def __init__(self, failures_before_success: int) -> None:
        self.failures_before_success = failures_before_success
        self.calls: list[LLMRequest] = []

    @property
    def provider_name(self) -> str:
        return "retry-adapter"

    def outbound_request_binding(self, request: LLMRequest) -> tuple[str, str] | None:
        return ("POST", "https://provider.example.test/v1/complete")

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        if len(self.calls) <= self.failures_before_success:
            raise ApplicationError("retry me", type="RateLimitError")
        return LLMResponse(
            content="retry-ok",
            tokens_used=17,
            model=request.model,
            provider="openai",
            finish_reason="stop",
        )


def _make_input(*, protect_outbound_request: bool = False) -> WorkflowInput:
    task_id = str(uuid4())
    return WorkflowInput(
        task_id=task_id,
        prompt="Retry-token test prompt",
        agent_type="general",
        requester_id="retry-user",
        protect_outbound_request=protect_outbound_request,
        session_id=f"session-{task_id}",
    )


async def _run_retry_workflow(
    *,
    failures_before_success: int,
    protect_outbound_request: bool = False,
    session_mgr: SessionManager | None = None,
    audit_logger: MagicMock | None = None,
) -> tuple[WorkflowOutput, _RetryAdapter, SessionManager, MagicMock]:
    manager = session_mgr or SessionManager()
    audit = audit_logger or MagicMock(spec=AuditLogger)
    adapter = _RetryAdapter(failures_before_success)
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=True, action="allow", reasons=[], fields=[])
    )
    activities = AegisActivities(
        adapter=adapter,
        session_mgr=manager,
        audit_logger=audit,
        policy_engine=policy_engine,
    )
    workflow_audit = WorkflowAuditActivities(audit_logger=audit)
    wf_input = _make_input(protect_outbound_request=protect_outbound_request)

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
                workflow_audit.record_event,
            ],
        ):
            result: WorkflowOutput = await env.client.execute_workflow(
                AgentTaskWorkflow.run,
                wf_input,
                id=wf_input.task_id,
                task_queue=_TASK_QUEUE,
            )
    return result, adapter, manager, audit


def _protected_token_app(session_mgr: SessionManager) -> TestClient:
    app = FastAPI()

    @app.get("/protected")
    def protected(authorization: str | None = Header(default=None)) -> dict[str, str]:
        if authorization is None:
            raise HTTPException(status_code=401, detail="missing header")
        _, _, token = authorization.partition(" ")
        try:
            claims = session_mgr.validate_token(token)
        except TokenRevokedError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return {"jti": claims.jti}

    return TestClient(app, raise_server_exceptions=False)


def _protected_sender_constrained_app(session_mgr: SessionManager) -> TestClient:
    app = FastAPI()

    @app.post("/protected")
    def protected(
        authorization: str | None = Header(default=None),
        dpop: str | None = Header(default=None, alias="DPoP"),
    ) -> dict[str, str]:
        if authorization is None or dpop is None:
            raise HTTPException(status_code=401, detail="missing protected credentials")
        _, _, token = authorization.partition(" ")
        try:
            claims = session_mgr.validate_sender_constrained_token(
                token,
                dpop,
                http_method="POST",
                http_url="https://provider.example.test/v1/complete",
            )
        except (DPoPProofError, TokenRevokedError) as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return {"jti": claims.jti, "cnf_jkt": claims.cnf.jkt if claims.cnf is not None else ""}

    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.integration
class TestJitRetryRotation:
    """S2-3 unit and integration coverage for retry-time token rotation."""

    @pytest.mark.asyncio
    async def test_new_token_per_retry(self) -> None:
        _result, adapter, _session_mgr, _audit = await _run_retry_workflow(
            failures_before_success=1,
        )
        first_token = adapter.calls[0].metadata["aegis_token"]
        second_token = adapter.calls[1].metadata["aegis_token"]
        first_claims = jwt.get_unverified_claims(first_token)
        second_claims = jwt.get_unverified_claims(second_token)
        assert first_claims["jti"] != second_claims["jti"]

    @pytest.mark.asyncio
    async def test_sender_constrained_retry_rotates_proof_jti_and_preserves_cnf_binding(
        self,
    ) -> None:
        _result, adapter, session_mgr, _audit = await _run_retry_workflow(
            failures_before_success=1,
            protect_outbound_request=True,
        )
        first_token = adapter.calls[0].metadata["aegis_token"]
        second_token = adapter.calls[1].metadata["aegis_token"]
        first_proof = adapter.calls[0].metadata["aegis_dpop_proof"]
        second_proof = adapter.calls[1].metadata["aegis_dpop_proof"]

        first_claims = jwt.get_unverified_claims(first_token)
        second_claims = session_mgr.validate_token(second_token)
        first_proof_claims = jwt.get_unverified_claims(first_proof)
        second_proof_claims = jwt.get_unverified_claims(second_proof)

        assert first_claims["jti"] != second_claims.jti
        assert first_proof_claims["jti"] != second_proof_claims["jti"]
        assert first_claims["cnf"] is not None
        assert second_claims.cnf is not None
        assert first_claims["cnf"]["jkt"] == second_claims.cnf.jkt

    @pytest.mark.asyncio
    async def test_prior_jti_rejected_after_retry(self) -> None:
        _result, adapter, session_mgr, _audit = await _run_retry_workflow(failures_before_success=1)
        first_token = adapter.calls[0].metadata["aegis_token"]
        client = _protected_token_app(session_mgr)
        response = client.get("/protected", headers={"Authorization": f"Bearer {first_token}"})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_prior_sender_constrained_token_or_proof_rejected_after_retry(self) -> None:
        _result, adapter, session_mgr, _audit = await _run_retry_workflow(
            failures_before_success=1,
            protect_outbound_request=True,
        )
        first_token = adapter.calls[0].metadata["aegis_token"]
        second_token = adapter.calls[1].metadata["aegis_token"]
        first_proof = adapter.calls[0].metadata["aegis_dpop_proof"]

        client = _protected_sender_constrained_app(session_mgr)
        response = client.post(
            "/protected",
            headers={
                "Authorization": f"Bearer {first_token}",
                "DPoP": first_proof,
            },
        )

        assert response.status_code == 401
        with pytest.raises(DPoPProofError, match="ath mismatch"):
            session_mgr.validate_sender_constrained_token(
                second_token,
                first_proof,
                http_method="POST",
                http_url="https://provider.example.test/v1/complete",
            )

    @pytest.mark.asyncio
    async def test_token_scope_preserved_on_reissue(self) -> None:
        _result, adapter, _session_mgr, _audit = await _run_retry_workflow(
            failures_before_success=1,
        )
        first_claims = jwt.get_unverified_claims(adapter.calls[0].metadata["aegis_token"])
        second_claims = jwt.get_unverified_claims(adapter.calls[1].metadata["aegis_token"])
        assert first_claims["agent_type"] == second_claims["agent_type"]
        assert first_claims["session_id"] == second_claims["session_id"]
        assert first_claims["allowed_actions"] == second_claims["allowed_actions"]

    @pytest.mark.asyncio
    async def test_sender_constrained_scope_preserved_on_reissue(self) -> None:
        _result, adapter, _session_mgr, _audit = await _run_retry_workflow(
            failures_before_success=1,
            protect_outbound_request=True,
        )
        first_claims = jwt.get_unverified_claims(adapter.calls[0].metadata["aegis_token"])
        second_claims = jwt.get_unverified_claims(adapter.calls[1].metadata["aegis_token"])

        assert first_claims["agent_type"] == second_claims["agent_type"]
        assert first_claims["session_id"] == second_claims["session_id"]
        assert first_claims["allowed_actions"] == second_claims["allowed_actions"]
        assert first_claims["cnf"]["jkt"] == second_claims["cnf"]["jkt"]

    @pytest.mark.asyncio
    async def test_jti_uniqueness_across_retried_chain(self) -> None:
        audit = MagicMock(spec=AuditLogger)
        _result, _adapter, _session_mgr, audit_logger = await _run_retry_workflow(
            failures_before_success=3,
            audit_logger=audit,
        )
        token_events = [
            call.kwargs["jti"]
            for call in audit_logger.stage_event.call_args_list
            if call.args and call.args[0] in {"token.issued", "token.reissued"}
        ]
        assert len(token_events) == 4
        assert len(set(token_events)) == 4
        for jti in token_events:
            UUID(jti)

    @pytest.mark.asyncio
    async def test_sender_constrained_proof_jti_uniqueness_across_retried_chain(self) -> None:
        _result, adapter, _session_mgr, _audit = await _run_retry_workflow(
            failures_before_success=3,
            protect_outbound_request=True,
        )
        proof_jtis = []
        for call in adapter.calls:
            proof_claims = jwt.get_unverified_claims(call.metadata["aegis_dpop_proof"])
            proof_jtis.append(proof_claims["jti"])

        assert len(proof_jtis) == 4
        assert len(set(proof_jtis)) == 4
        for jti in proof_jtis:
            UUID(jti)

    def test_no_token_reuse_even_same_millisecond(self) -> None:
        session_mgr = SessionManager()
        with freeze_time("2026-03-06T15:00:00Z"):
            first = session_mgr.issue_token(
                agent_type="general",
                requester_id="retry-user",
                session_id="session-freeze",
                allowed_actions=["llm:complete"],
                rotation_key="llm:freeze",
            )
            second = session_mgr.issue_token(
                agent_type="general",
                requester_id="retry-user",
                session_id="session-freeze",
                allowed_actions=["llm:complete"],
                rotation_key="llm:freeze",
            )
        first_claims = jwt.get_unverified_claims(first)
        second_claims = jwt.get_unverified_claims(second)
        assert first_claims["iat"] == second_claims["iat"]
        assert first_claims["exp"] == second_claims["exp"]
        assert first_claims["jti"] != second_claims["jti"]

    def test_sender_constrained_retry_emits_fresh_proofs_same_millisecond(self) -> None:
        session_mgr = SessionManager()
        private_key_pem, public_jwk = session_mgr.generate_dpop_key_pair()
        with freeze_time("2026-03-06T15:00:00Z"):
            first_token = session_mgr.issue_sender_constrained_token(
                agent_type="general",
                requester_id="retry-user",
                public_jwk=public_jwk,
                session_id="session-freeze",
                allowed_actions=["llm.invoke"],
                rotation_key="scheduler-adapter:freeze",
            )
            first_proof = session_mgr.issue_dpop_proof(
                private_key_pem,
                public_jwk,
                http_method="POST",
                http_url="https://provider.example.test/v1/complete",
                access_token=first_token,
            )
            second_token = session_mgr.issue_sender_constrained_token(
                agent_type="general",
                requester_id="retry-user",
                public_jwk=public_jwk,
                session_id="session-freeze",
                allowed_actions=["llm.invoke"],
                rotation_key="scheduler-adapter:freeze",
            )
            second_proof = session_mgr.issue_dpop_proof(
                private_key_pem,
                public_jwk,
                http_method="POST",
                http_url="https://provider.example.test/v1/complete",
                access_token=second_token,
            )

        first_claims = jwt.get_unverified_claims(first_token)
        second_claims = jwt.get_unverified_claims(second_token)
        first_proof_claims = jwt.get_unverified_claims(first_proof)
        second_proof_claims = jwt.get_unverified_claims(second_proof)

        assert first_claims["iat"] == second_claims["iat"]
        assert first_claims["exp"] == second_claims["exp"]
        assert first_claims["jti"] != second_claims["jti"]
        assert first_claims["cnf"]["jkt"] == second_claims["cnf"]["jkt"]
        assert first_proof_claims["iat"] == second_proof_claims["iat"]
        assert first_proof_claims["jti"] != second_proof_claims["jti"]
