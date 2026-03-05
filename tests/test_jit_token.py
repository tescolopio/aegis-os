"""JIT session token injection tests – S1-3.

Covers:
  1. Token present: every ``LLMRequest`` that reaches the adapter carries
     ``metadata["aegis_token"]`` containing a valid HS256 JWT with the correct
     ``agent_type`` claim.
  2. Token scope: an existing token scoped to ``finance`` is rejected with
     :class:`TokenScopeError` when the request declares ``agent_type="hr"``.
     The LLM adapter must never be called.
  3. Expired token: a token with ``exp`` in the past raises
     :class:`TokenExpiredError` and the orchestrator emits a ``token_expired``
     audit event before raising.
  4. ``jti`` uniqueness: 100 sequential tasks each receive a distinct,
     well-formed UUID4 ``jti`` claim – no token is ever reused.
"""

from __future__ import annotations

import time
import uuid as uuid_mod
from unittest.mock import AsyncMock, MagicMock

import pytest
from jose import jwt

from src.adapters.base import BaseAdapter, LLMRequest, LLMResponse
from src.audit_vault.logger import AuditLogger
from src.config import settings
from src.control_plane.orchestrator import (
    Orchestrator,
    OrchestratorRequest,
)
from src.governance.guardrails import Guardrails
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager, TokenExpiredError, TokenScopeError

# ---------------------------------------------------------------------------
# Shared helpers / constants
# ---------------------------------------------------------------------------

_BASE_REQUEST = OrchestratorRequest(
    prompt="Analyse the quarterly figures.",
    agent_type="general",
    requester_id="user-jit-test",
    model="stub",
)


def _make_policy_engine(allowed: bool = True, action: str = "allow") -> PolicyEngine:
    pe = MagicMock(spec=PolicyEngine)
    pe.evaluate = AsyncMock(return_value=PolicyResult(allowed=allowed, action=action))
    return pe


def _make_stub_adapter(content: str = "response") -> BaseAdapter:
    adapter = MagicMock(spec=BaseAdapter)
    adapter.complete = AsyncMock(
        return_value=LLMResponse(
            content=content,
            tokens_used=5,
            model="stub",
            provider="stub",
            finish_reason="stop",
        )
    )
    return adapter


def _make_orchestrator(
    *,
    adapter: BaseAdapter | None = None,
    session_mgr: SessionManager | None = None,
    policy_engine: PolicyEngine | None = None,
    audit: AuditLogger | None = None,
) -> Orchestrator:
    return Orchestrator(
        adapter=adapter or _make_stub_adapter(),
        guardrails=Guardrails(),
        policy_engine=policy_engine or _make_policy_engine(),
        session_mgr=session_mgr or SessionManager(),
        audit_logger=audit or MagicMock(spec=AuditLogger),
    )


def _forge_token(agent_type: str, requester_id: str, exp_offset: float) -> str:
    """Produce a signed JWT whose ``exp`` is ``now + exp_offset``."""
    now = time.time()
    return jwt.encode(
        {
            "jti": str(uuid_mod.uuid4()),
            "sub": requester_id,
            "agent_type": agent_type,
            "iat": now,
            "exp": now + exp_offset,
            "metadata": {},
        },
        settings.token_secret_key,
        algorithm=settings.token_algorithm,
    )


# ---------------------------------------------------------------------------
# 1. Token present in every LLM adapter call
# ---------------------------------------------------------------------------


class TestTokenPresent:
    """Every LLMRequest that reaches the adapter must carry ``metadata["aegis_token"]``."""

    @pytest.mark.asyncio
    async def test_aegis_token_key_present_in_metadata(self) -> None:
        """The ``aegis_token`` key must exist in ``LLMRequest.metadata``."""
        captured: list[LLMRequest] = []

        async def _capture(req: LLMRequest) -> LLMResponse:
            captured.append(req)
            return LLMResponse(content="ok", tokens_used=5, model="stub", provider="stub")

        adapter = MagicMock(spec=BaseAdapter)
        adapter.complete = _capture

        orch = _make_orchestrator(adapter=adapter)
        await orch.run(_BASE_REQUEST)

        assert len(captured) == 1
        assert "aegis_token" in captured[0].metadata, (
            "LLMRequest.metadata must contain 'aegis_token'"
        )

    @pytest.mark.asyncio
    async def test_aegis_token_is_valid_jwt(self) -> None:
        """``metadata["aegis_token"]`` must be a decodable, valid JWT."""
        captured: list[LLMRequest] = []

        async def _capture(req: LLMRequest) -> LLMResponse:
            captured.append(req)
            return LLMResponse(content="ok", tokens_used=5, model="stub", provider="stub")

        adapter = MagicMock(spec=BaseAdapter)
        adapter.complete = _capture

        orch = _make_orchestrator(adapter=adapter)
        await orch.run(_BASE_REQUEST)

        token = captured[0].metadata["aegis_token"]
        # Must decode without error (this also verifies sig and expiry)
        payload = jwt.decode(
            token,
            settings.token_secret_key,
            algorithms=[settings.token_algorithm],
        )
        assert isinstance(payload, dict), "Decoded payload must be a dict"

    @pytest.mark.asyncio
    async def test_aegis_token_algorithm_is_hs256(self) -> None:
        """The JWT must be signed with HS256."""
        captured: list[LLMRequest] = []

        async def _capture(req: LLMRequest) -> LLMResponse:
            captured.append(req)
            return LLMResponse(content="ok", tokens_used=5, model="stub", provider="stub")

        adapter = MagicMock(spec=BaseAdapter)
        adapter.complete = _capture

        orch = _make_orchestrator(adapter=adapter)
        await orch.run(_BASE_REQUEST)

        token = captured[0].metadata["aegis_token"]
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "HS256", (
            f"Expected HS256 but got {header['alg']!r}"
        )

    @pytest.mark.asyncio
    async def test_aegis_token_carries_correct_agent_type(self) -> None:
        """The token's ``agent_type`` claim must match the request's agent type."""
        captured: list[LLMRequest] = []

        async def _capture(req: LLMRequest) -> LLMResponse:
            captured.append(req)
            return LLMResponse(content="ok", tokens_used=5, model="stub", provider="stub")

        adapter = MagicMock(spec=BaseAdapter)
        adapter.complete = _capture

        request = OrchestratorRequest(
            prompt="Scope check test.",
            agent_type="it",
            requester_id="user-it",
            model="stub",
        )

        orch = _make_orchestrator(adapter=adapter)
        await orch.run(request)

        token = captured[0].metadata["aegis_token"]
        payload = jwt.decode(
            token,
            settings.token_secret_key,
            algorithms=[settings.token_algorithm],
        )
        assert payload["agent_type"] == "it"

    @pytest.mark.asyncio
    async def test_token_contains_jti_claim(self) -> None:
        """The JIT token must contain a ``jti`` (JWT ID) claim."""
        captured: list[LLMRequest] = []

        async def _capture(req: LLMRequest) -> LLMResponse:
            captured.append(req)
            return LLMResponse(content="ok", tokens_used=5, model="stub", provider="stub")

        adapter = MagicMock(spec=BaseAdapter)
        adapter.complete = _capture

        orch = _make_orchestrator(adapter=adapter)
        await orch.run(_BASE_REQUEST)

        token = captured[0].metadata["aegis_token"]
        payload = jwt.decode(
            token,
            settings.token_secret_key,
            algorithms=[settings.token_algorithm],
        )
        assert "jti" in payload, "Token must carry a jti claim"
        # Must be a valid UUID
        uuid_mod.UUID(payload["jti"])  # raises ValueError if malformed

    @pytest.mark.asyncio
    async def test_token_issued_audit_event_emitted(self) -> None:
        """A ``token_issued`` audit event including the ``jti`` must be emitted
        for every freshly issued token."""
        audit = MagicMock(spec=AuditLogger)
        orch = _make_orchestrator(audit=audit)

        await orch.run(_BASE_REQUEST)

        # Collect all stage_event() calls (A1-2: orchestrator emits via stage_event)
        stage_events = [c.args[0] for c in audit.stage_event.call_args_list]
        assert "token.issued" in stage_events, (
            f"Expected 'token.issued' audit event; got {stage_events!r}"
        )
        # The specific token.issued call must carry a jti kwarg
        token_issued_calls = [
            c for c in audit.stage_event.call_args_list if c.args[0] == "token.issued"
        ]
        assert len(token_issued_calls) == 1
        kwargs = token_issued_calls[0].kwargs
        assert "jti" in kwargs, "token_issued audit event must include jti"
        uuid_mod.UUID(str(kwargs["jti"]))  # must be a valid UUID string

    @pytest.mark.asyncio
    async def test_existing_valid_token_passed_through(self) -> None:
        """When the caller supplies a valid, same-scope ``session_token``, it
        must be forwarded as ``aegis_token`` in the LLM request – no new token
        is issued."""
        existing_token = _forge_token(
            agent_type=_BASE_REQUEST.agent_type,
            requester_id=_BASE_REQUEST.requester_id,
            exp_offset=900.0,
        )
        request = _BASE_REQUEST.model_copy(update={"session_token": existing_token})

        captured: list[LLMRequest] = []

        async def _capture(req: LLMRequest) -> LLMResponse:
            captured.append(req)
            return LLMResponse(content="ok", tokens_used=5, model="stub", provider="stub")

        adapter = MagicMock(spec=BaseAdapter)
        adapter.complete = _capture

        orch = _make_orchestrator(adapter=adapter)
        await orch.run(request)

        assert captured[0].metadata["aegis_token"] == existing_token


# ---------------------------------------------------------------------------
# 2. Token scope enforcement
# ---------------------------------------------------------------------------


class TestTokenScope:
    """A token issued for one ``agent_type`` must be rejected for a different one."""

    @pytest.mark.asyncio
    async def test_scope_mismatch_raises_token_scope_error(self) -> None:
        """Supplying a ``finance``-scoped token with ``agent_type='hr'`` must
        raise :class:`TokenScopeError`."""
        sm = SessionManager()
        finance_token = sm.issue_token(agent_type="finance", requester_id="user-test")

        request = OrchestratorRequest(
            prompt="HR query.",
            agent_type="hr",
            requester_id="user-test",
            session_token=finance_token,
            model="stub",
        )

        orch = _make_orchestrator(session_mgr=sm)

        with pytest.raises(TokenScopeError):
            await orch.run(request)

    @pytest.mark.asyncio
    async def test_adapter_not_called_on_scope_error(self) -> None:
        """The LLM adapter must never be invoked when scope validation fails."""
        sm = SessionManager()
        finance_token = sm.issue_token(agent_type="finance", requester_id="user-test")

        request = OrchestratorRequest(
            prompt="HR query.",
            agent_type="hr",
            requester_id="user-test",
            session_token=finance_token,
            model="stub",
        )

        adapter = _make_stub_adapter()
        orch = _make_orchestrator(adapter=adapter, session_mgr=sm)

        with pytest.raises(TokenScopeError):
            await orch.run(request)

        adapter.complete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_scope_violation_emits_audit_event(self) -> None:
        """A ``token_scope_violation`` warning audit event must be emitted."""
        sm = SessionManager()
        finance_token = sm.issue_token(agent_type="finance", requester_id="user-test")

        request = OrchestratorRequest(
            prompt="HR query.",
            agent_type="hr",
            requester_id="user-test",
            session_token=finance_token,
            model="stub",
        )

        audit = MagicMock(spec=AuditLogger)
        orch = _make_orchestrator(session_mgr=sm, audit=audit)

        with pytest.raises(TokenScopeError):
            await orch.run(request)

        stage_events = [c.args[0] for c in audit.stage_event.call_args_list]
        assert "token.scope_violation" in stage_events, (
            f"Expected 'token.scope_violation' audit event; got {stage_events!r}"
        )

    @pytest.mark.asyncio
    async def test_matching_scope_succeeds(self) -> None:
        """A token whose ``agent_type`` matches the request must be accepted
        without raising."""
        sm = SessionManager()
        finance_token = sm.issue_token(agent_type="finance", requester_id="user-test")

        request = OrchestratorRequest(
            prompt="Finance query.",
            agent_type="finance",
            requester_id="user-test",
            session_token=finance_token,
            model="stub",
        )

        orch = _make_orchestrator(session_mgr=sm)
        # Should not raise
        result = await orch.run(request)
        assert result.session_token == finance_token

    @pytest.mark.asyncio
    async def test_scope_error_before_adapter(self) -> None:
        """``TokenScopeError`` must be raised in Stage 3 – before Stage 4.
        Assert by verifying the adapter was never awaited."""
        sm = SessionManager()
        it_token = sm.issue_token(agent_type="it", requester_id="user-x")

        request = OrchestratorRequest(
            prompt="Hello.",
            agent_type="legal",  # different scope
            requester_id="user-x",
            session_token=it_token,
            model="stub",
        )

        adapter = _make_stub_adapter()
        orch = _make_orchestrator(adapter=adapter, session_mgr=sm)

        with pytest.raises(TokenScopeError):
            await orch.run(request)

        adapter.complete.assert_not_awaited()


# ---------------------------------------------------------------------------
# 3. Expired token handling
# ---------------------------------------------------------------------------


class TestTokenExpired:
    """An expired JIT token must be rejected with ``TokenExpiredError``."""

    @pytest.mark.asyncio
    async def test_expired_token_raises_token_expired_error(self) -> None:
        """A token with ``exp`` 1 second in the past must raise :class:`TokenExpiredError`."""
        expired_token = _forge_token(
            agent_type="general",
            requester_id="user-test",
            exp_offset=-1.0,
        )

        request = OrchestratorRequest(
            prompt="Hello.",
            agent_type="general",
            requester_id="user-test",
            session_token=expired_token,
            model="stub",
        )

        orch = _make_orchestrator()

        with pytest.raises(TokenExpiredError):
            await orch.run(request)

    @pytest.mark.asyncio
    async def test_expired_token_adapter_not_called(self) -> None:
        """The LLM adapter must never be called when the token is expired."""
        expired_token = _forge_token(
            agent_type="general",
            requester_id="user-test",
            exp_offset=-1.0,
        )

        request = OrchestratorRequest(
            prompt="Hello.",
            agent_type="general",
            requester_id="user-test",
            session_token=expired_token,
            model="stub",
        )

        adapter = _make_stub_adapter()
        orch = _make_orchestrator(adapter=adapter)

        with pytest.raises(TokenExpiredError):
            await orch.run(request)

        adapter.complete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_expired_token_emits_audit_event(self) -> None:
        """A ``token_expired`` warning audit event must be emitted before raising."""
        expired_token = _forge_token(
            agent_type="general",
            requester_id="user-test",
            exp_offset=-1.0,
        )

        request = OrchestratorRequest(
            prompt="Hello.",
            agent_type="general",
            requester_id="user-test",
            session_token=expired_token,
            model="stub",
        )

        audit = MagicMock(spec=AuditLogger)
        orch = _make_orchestrator(audit=audit)

        with pytest.raises(TokenExpiredError):
            await orch.run(request)

        stage_events = [c.args[0] for c in audit.stage_event.call_args_list]
        assert "token.expired" in stage_events, (
            f"Expected 'token.expired' audit event; got {stage_events!r}"
        )

    @pytest.mark.asyncio
    async def test_expired_token_audit_includes_requester(self) -> None:
        """The ``token_expired`` audit event must carry ``requester_id`` and
        ``agent_type`` so the incident can be correlated."""
        expired_token = _forge_token(
            agent_type="finance",
            requester_id="user-abc",
            exp_offset=-5.0,
        )

        request = OrchestratorRequest(
            prompt="Hello.",
            agent_type="finance",
            requester_id="user-abc",
            session_token=expired_token,
            model="stub",
        )

        audit = MagicMock(spec=AuditLogger)
        orch = _make_orchestrator(audit=audit)

        with pytest.raises(TokenExpiredError):
            await orch.run(request)

        expired_calls = [
            c for c in audit.stage_event.call_args_list if c.args[0] == "token.expired"
        ]
        assert len(expired_calls) >= 1
        kw = expired_calls[0].kwargs
        assert kw.get("requester_id") == "user-abc"
        assert kw.get("agent_type") == "finance"

    @pytest.mark.asyncio
    async def test_valid_token_not_rejected(self) -> None:
        """A freshly issued, non-expired token must not trigger ``TokenExpiredError``."""
        valid_token = _forge_token(
            agent_type="general",
            requester_id="user-test",
            exp_offset=900.0,  # 15 minutes in the future
        )

        request = OrchestratorRequest(
            prompt="Hello.",
            agent_type="general",
            requester_id="user-test",
            session_token=valid_token,
            model="stub",
        )

        # Should not raise
        orch = _make_orchestrator()
        result = await orch.run(request)
        assert result.session_token == valid_token


# ---------------------------------------------------------------------------
# 4. jti uniqueness across sequential tasks
# ---------------------------------------------------------------------------


class TestJtiUniqueness:
    """Every issued token must carry a globally unique ``jti`` claim."""

    @pytest.mark.asyncio
    async def test_100_sequential_tasks_produce_distinct_jti(self) -> None:
        """Run 100 orchestrator tasks in sequence; assert all 100 ``jti`` values
        are distinct, well-formed UUID4 strings.

        This is the integration-style verification that the ``jti`` uniqueness
        invariant holds under realistic repeated execution (no token reuse across
        Temporal retries or consecutive API calls).
        """
        orch = _make_orchestrator()

        jti_values: list[str] = []
        for _ in range(100):
            result = await orch.run(_BASE_REQUEST)
            payload = jwt.decode(
                result.session_token,
                settings.token_secret_key,
                algorithms=[settings.token_algorithm],
            )
            jti_values.append(payload["jti"])

        # All 100 values must be present
        assert len(jti_values) == 100

        # All must be distinct
        assert len(set(jti_values)) == 100, (
            f"Expected 100 unique jti values but found {len(set(jti_values))} distinct values"
        )

        # Each must be a valid UUID
        for jti in jti_values:
            try:
                uuid_mod.UUID(jti)
            except ValueError:
                pytest.fail(f"jti {jti!r} is not a valid UUID")

    @pytest.mark.asyncio
    async def test_jti_uniqueness_confirmed_via_audit_events(self) -> None:
        """Every ``token_issued`` audit event must carry a unique ``jti``.

        Collects 20 sequential emissions from the audit logger and verifies
        no ``jti`` is reused.
        """
        audit = MagicMock(spec=AuditLogger)
        orch = _make_orchestrator(audit=audit)

        for _ in range(20):
            await orch.run(_BASE_REQUEST)

        issued_calls = [
            c for c in audit.stage_event.call_args_list if c.args[0] == "token.issued"
        ]
        assert len(issued_calls) == 20, (
            f"Expected 20 token.issued events; got {len(issued_calls)}"
        )

        jti_set = {c.kwargs["jti"] for c in issued_calls}
        assert len(jti_set) == 20, (
            f"Expected 20 unique jti values in audit log; got {len(jti_set)}"
        )
