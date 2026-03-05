"""W1-3 — Prometheus metrics emit on every task completion and every error path.

Requirements covered
--------------------
1. Unit — counter increment.
2. Unit — gauge accuracy.
3. Unit — error paths (all five main orchestrator stages + watchdog stages).
4. Negative — no metric on aborted requests (validation failure before orchestrator).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose.exceptions import ExpiredSignatureError as JoseExpiredSignatureError
from prometheus_client import REGISTRY

import src.control_plane.router as router_module
from src.adapters.base import BaseAdapter, LLMRequest, LLMResponse
from src.audit_vault.logger import AuditLogger
from src.control_plane.orchestrator import Orchestrator, OrchestratorRequest, OrchestratorResult
from src.governance.guardrails import Guardrails, MaskResult, PromptInjectionError
from src.governance.policy_engine.opa_client import OpaUnavailableError, PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager
from src.watchdog.budget_enforcer import BudgetEnforcer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample(metric_name: str, labels: dict[str, str]) -> float:
    """Read a single scalar sample from the global Prometheus registry.

    Returns 0.0 when the label combination has not yet been observed (i.e.
    the metric counter has never been incremented for these labels).
    """
    value = REGISTRY.get_sample_value(metric_name, labels)
    return float(value) if value is not None else 0.0


_STUB_LLM = LLMResponse(
    content="stub response",
    tokens_used=42,
    model="gpt-4o-mini",
    provider="stub",
    finish_reason="stop",
)


class _OkAdapter(BaseAdapter):
    """Adapter that always succeeds and returns _STUB_LLM."""

    @property
    def provider_name(self) -> str:  # noqa: D102
        return "stub"

    async def complete(self, request: LLMRequest) -> LLMResponse:  # noqa: D102
        return _STUB_LLM


def _make_ok_guardrails() -> Guardrails:
    """Return a passthrough Guardrails mock."""
    g = MagicMock(spec=Guardrails)
    g.check_prompt_injection.return_value = None
    g.mask_pii.return_value = MaskResult(text="clean prompt", found_types=[])
    g.scrub.return_value = MaskResult(text="clean prompt", found_types=[])
    return g


def _make_ok_policy() -> PolicyEngine:
    """Return a PolicyEngine mock that always allows."""
    pe = MagicMock(spec=PolicyEngine)

    async def _evaluate(*_a: Any, **_kw: Any) -> PolicyResult:
        return PolicyResult(allowed=True)

    pe.evaluate = _evaluate
    return pe


def _make_ok_session_mgr() -> SessionManager:
    """Return a SessionManager mock that issues tokens and validates them."""
    sm = MagicMock(spec=SessionManager)
    sm.issue_token.return_value = "jwt.test.token"
    return sm


def _make_orchestrator(**overrides: Any) -> Orchestrator:
    """Build an Orchestrator with sensible passthrough mocks for every dependency."""
    return Orchestrator(
        adapter=overrides.get("adapter", _OkAdapter()),
        guardrails=overrides.get("guardrails", _make_ok_guardrails()),
        policy_engine=overrides.get("policy_engine", _make_ok_policy()),
        session_mgr=overrides.get("session_mgr", _make_ok_session_mgr()),
        audit_logger=AuditLogger("test"),
        tracer=None,
        budget_enforcer=overrides.get("budget_enforcer"),
        loop_detector=overrides.get("loop_detector"),
    )


_BASE_REQUEST = OrchestratorRequest(
    prompt="summarise quarterly report",
    agent_type="finance",
    requester_id="tester-001",
    model="gpt-4o-mini",
)


# ---------------------------------------------------------------------------
# 1. Unit — counter increment
# ---------------------------------------------------------------------------


class TestCounterIncrement:
    """aegis_tokens_consumed_total increments by the exact token count."""

    def test_counter_delta_equals_tokens_recorded(self) -> None:
        """record_tokens(n) must add exactly n to the counter for that agent_type."""
        enforcer = BudgetEnforcer()
        sid = uuid4()
        enforcer.create_session(sid, agent_type="counter_test", budget_limit_usd=Decimal("50.00"))

        before = _sample("aegis_tokens_consumed_total", {"agent_type": "counter_test"})
        enforcer.record_tokens(sid, 99)
        after = _sample("aegis_tokens_consumed_total", {"agent_type": "counter_test"})

        assert (after - before) == pytest.approx(99.0)

    def test_counter_multiple_calls_accumulate(self) -> None:
        """Successive record_tokens calls accumulate in the same counter label."""
        enforcer = BudgetEnforcer()
        sid = uuid4()
        enforcer.create_session(
            sid, agent_type="counter_accum", budget_limit_usd=Decimal("100.00")
        )

        before = _sample("aegis_tokens_consumed_total", {"agent_type": "counter_accum"})
        enforcer.record_tokens(sid, 10)
        enforcer.record_tokens(sid, 20)
        enforcer.record_tokens(sid, 30)
        after = _sample("aegis_tokens_consumed_total", {"agent_type": "counter_accum"})

        assert (after - before) == pytest.approx(60.0)

    def test_different_agent_types_have_independent_counters(self) -> None:
        """record_tokens for agent_type A must not affect the counter for agent_type B."""
        enforcer = BudgetEnforcer()
        sid_a, sid_b = uuid4(), uuid4()
        enforcer.create_session(sid_a, agent_type="typeA_w1r3", budget_limit_usd=Decimal("10"))
        enforcer.create_session(sid_b, agent_type="typeB_w1r3", budget_limit_usd=Decimal("10"))

        before_b = _sample("aegis_tokens_consumed_total", {"agent_type": "typeB_w1r3"})
        enforcer.record_tokens(sid_a, 50)
        after_b = _sample("aegis_tokens_consumed_total", {"agent_type": "typeB_w1r3"})

        assert (after_b - before_b) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# 2. Unit — gauge accuracy
# ---------------------------------------------------------------------------


class TestGaugeAccuracy:
    """aegis_budget_remaining_usd reflects limit − spent to four decimal places."""

    def test_gauge_equals_limit_after_session_creation(self) -> None:
        """Gauge must equal the full limit immediately after create_session."""
        enforcer = BudgetEnforcer()
        sid = uuid4()
        enforcer.create_session(sid, agent_type="gauge_init", budget_limit_usd=Decimal("5.0000"))

        gauge = _sample("aegis_budget_remaining_usd", {"session_id": str(sid)})
        assert gauge == pytest.approx(5.0, abs=1e-4)

    def test_gauge_accuracy_after_spend(self) -> None:
        """Gauge must equal limit − spent to four decimal places after record_spend."""
        enforcer = BudgetEnforcer()
        sid = uuid4()
        enforcer.create_session(sid, agent_type="gauge_spend", budget_limit_usd=Decimal("10.0000"))
        enforcer.record_spend(sid, Decimal("3.4567"))

        gauge = _sample("aegis_budget_remaining_usd", {"session_id": str(sid)})
        assert gauge == pytest.approx(6.5433, abs=1e-4)

    def test_gauge_clamps_to_zero_when_budget_exhausted(self) -> None:
        """Gauge must not go negative — it is clamped to zero on over-spend."""
        enforcer = BudgetEnforcer()
        sid = uuid4()
        enforcer.create_session(
            sid, agent_type="gauge_zero", budget_limit_usd=Decimal("0.0001")
        )
        with pytest.raises(Exception):  # BudgetExceededError
            enforcer.record_spend(sid, Decimal("9.9999"))

        gauge = _sample("aegis_budget_remaining_usd", {"session_id": str(sid)})
        assert gauge == pytest.approx(0.0, abs=1e-6)

    def test_gauge_tracks_multiple_spends(self) -> None:
        """Each successive spend must reduce the gauge by exactly that amount."""
        enforcer = BudgetEnforcer()
        sid = uuid4()
        enforcer.create_session(
            sid, agent_type="gauge_multi", budget_limit_usd=Decimal("100.0000")
        )

        enforcer.record_spend(sid, Decimal("10.0000"))
        g1 = _sample("aegis_budget_remaining_usd", {"session_id": str(sid)})
        assert g1 == pytest.approx(90.0, abs=1e-4)

        enforcer.record_spend(sid, Decimal("25.5000"))
        g2 = _sample("aegis_budget_remaining_usd", {"session_id": str(sid)})
        assert g2 == pytest.approx(64.5, abs=1e-4)


# ---------------------------------------------------------------------------
# 3. Unit — error paths
# ---------------------------------------------------------------------------


class TestErrorPaths:
    """aegis_orchestrator_errors_total fires on every orchestrator stage failure."""

    async def _run_and_expect_error(
        self,
        orc: Orchestrator,
        request: OrchestratorRequest,
        stage: str,
    ) -> None:
        """Run the pipeline, expect an exception, assert the error counter incremented."""
        before = _sample(
            "aegis_orchestrator_errors_total",
            {"stage": stage, "agent_type": request.agent_type},
        )
        with pytest.raises(Exception):
            await orc.run(request)
        after = _sample(
            "aegis_orchestrator_errors_total",
            {"stage": stage, "agent_type": request.agent_type},
        )
        assert (after - before) == pytest.approx(1.0), (
            f"Expected orchestrator_errors[stage={stage!r}] to increment by 1; "
            f"delta was {after - before}"
        )

    async def test_stage1_guardrails_pre_error_increments_counter(self) -> None:
        """Stage 1 prompt-injection detection must emit an error counter on failure."""
        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.side_effect = PromptInjectionError("injection detected")
        orc = _make_orchestrator(guardrails=guardrails)
        await self._run_and_expect_error(orc, _BASE_REQUEST, "pre_pii_scrub")

    async def test_stage2_opa_eval_error_increments_counter(self) -> None:
        """Stage 2 OPA unavailability must emit an error counter on failure."""
        pe = MagicMock(spec=PolicyEngine)
        pe.evaluate = AsyncMock(side_effect=OpaUnavailableError("OPA down"))
        orc = _make_orchestrator(policy_engine=pe)
        await self._run_and_expect_error(orc, _BASE_REQUEST, "policy_eval")

    async def test_stage2_policy_denial_increments_counter(self) -> None:
        """Stage 2 policy denial (allow=False) must emit an error counter."""
        pe = MagicMock(spec=PolicyEngine)
        pe.evaluate = AsyncMock(return_value=PolicyResult(allowed=False, reasons=["denied"]))
        orc = _make_orchestrator(policy_engine=pe)
        await self._run_and_expect_error(orc, _BASE_REQUEST, "policy_eval")

    async def test_stage3_session_mgr_expired_token_increments_counter(self) -> None:
        """Stage 3 expired-token validation must emit an error counter."""
        sm = MagicMock(spec=SessionManager)
        sm.validate_token.side_effect = JoseExpiredSignatureError("expired")
        orc = _make_orchestrator(session_mgr=sm)
        # Provide a session_token so the code path runs validate_token()
        req = _BASE_REQUEST.model_copy(update={"session_token": "fake.jwt.token"})
        await self._run_and_expect_error(orc, req, "jit_token_issue")

    async def test_stage4_llm_adapter_error_increments_counter(self) -> None:
        """Stage 4 LLM adapter failure must emit an error counter."""

        class _FailAdapter(BaseAdapter):
            @property
            def provider_name(self) -> str:  # noqa: D102
                return "fail_stub"

            async def complete(self, r: LLMRequest) -> LLMResponse:
                raise RuntimeError("provider unavailable")

        orc = _make_orchestrator(adapter=_FailAdapter())
        await self._run_and_expect_error(orc, _BASE_REQUEST, "llm_invoke")

    async def test_stage5_guardrails_post_error_increments_counter(self) -> None:
        """Stage 5 post-sanitize failure must emit an error counter."""
        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.return_value = None
        # Pre-sanitize succeeds; post-sanitize (second call) raises
        call_count: list[int] = [0]

        def _side_effect(text: str) -> MaskResult:
            call_count[0] += 1
            if call_count[0] == 2:  # second mask_pii = stage 5
                raise RuntimeError("post-sanitize failure")
            return MaskResult(text=text, found_types=[])

        guardrails.mask_pii.side_effect = _side_effect
        orc = _make_orchestrator(guardrails=guardrails)
        await self._run_and_expect_error(orc, _BASE_REQUEST, "post_sanitize")

    async def test_watchdog_pre_error_increments_counter(self) -> None:
        """Stage 3.5 pre-LLM budget exhaustion must emit an error counter."""
        enforcer = BudgetEnforcer()
        sid = uuid4()
        # Exhaust the budget completely before the request
        enforcer.create_session(sid, agent_type="finance", budget_limit_usd=Decimal("0.000001"))
        with pytest.raises(Exception):
            enforcer.record_spend(sid, Decimal("1.00"))

        orc = _make_orchestrator(budget_enforcer=enforcer)
        req = _BASE_REQUEST.model_copy(update={"budget_session_id": sid})
        await self._run_and_expect_error(orc, req, "watchdog_pre")

    async def test_watchdog_record_error_increments_counter(self) -> None:
        """Stage 4.5 over-budget spend must emit a watchdog_record error counter."""
        enforcer = BudgetEnforcer()
        sid = uuid4()
        # Near the limit so the LLM response tokens push it over
        enforcer.create_session(sid, agent_type="finance", budget_limit_usd=Decimal("0.000001"))

        orc = _make_orchestrator(
            budget_enforcer=enforcer,
            # cost_per_token default ensures 42 tokens exceeds $0.000001 limit
        )
        req = _BASE_REQUEST.model_copy(update={"budget_session_id": sid})
        before = _sample(
            "aegis_orchestrator_errors_total",
            {"stage": "watchdog_record", "agent_type": "finance"},
        )
        with pytest.raises(Exception):
            await orc.run(req)
        after = _sample(
            "aegis_orchestrator_errors_total",
            {"stage": "watchdog_record", "agent_type": "finance"},
        )
        assert (after - before) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# 4. Negative — no metric on aborted requests
# ---------------------------------------------------------------------------


class TestNoMetricOnAbortedRequest:
    """Validation failures before the orchestrator must not increment any counter."""

    @pytest.fixture(autouse=True)
    def _restore_orchestrator(self) -> Any:  # type: ignore[override]
        original = router_module._orchestrator
        yield
        router_module._orchestrator = original

    def test_missing_required_field_does_not_increment_token_counter(self) -> None:
        """A 422 validation error must leave aegis_tokens_consumed_total unchanged.

        The FastAPI validation layer rejects malformed requests before the
        route handler executes, so the orchestrator is never called and
        ``record_tokens`` is never invoked.
        """
        # Mount a real-ish orchestrator so _require_orchestrator() doesn't fail,
        # but it must be a mock so it never actually calls record_tokens.
        mock_orc = MagicMock(spec=Orchestrator)
        mock_orc.run = AsyncMock(
            return_value=OrchestratorResult(
                task_id=uuid4(),
                response=_STUB_LLM,
                session_token="tok",
                sanitized_prompt="x",
                pii_found_in_prompt=[],
                pii_found_in_response=[],
            )
        )
        router_module.configure_orchestrator(mock_orc)
        app = FastAPI()
        app.include_router(router_module.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)

        # Any agent_type: read counter before and after
        before = _sample("aegis_tokens_consumed_total", {"agent_type": "finance"})

        # Send a payload missing all required fields
        resp = client.post("/api/v1/tasks", json={})
        assert resp.status_code == 422, f"Expected 422, got {resp.status_code}"

        after = _sample("aegis_tokens_consumed_total", {"agent_type": "finance"})
        assert (after - before) == pytest.approx(0.0), (
            "Token counter must not increment when request fails validation"
        )

    def test_orchestrator_never_called_on_validation_failure(self) -> None:
        """A 422 response must not trigger any orchestrator.run() calls."""
        mock_orc = MagicMock(spec=Orchestrator)
        mock_orc.run = AsyncMock()
        router_module.configure_orchestrator(mock_orc)
        app = FastAPI()
        app.include_router(router_module.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)

        # Missing required fields
        client.post("/api/v1/tasks", json={"agent_type": "finance"})

        mock_orc.run.assert_not_called()

    def test_error_counter_not_incremented_on_validation_failure(self) -> None:
        """aegis_orchestrator_errors_total must not increment on 422 validation errors."""
        mock_orc = MagicMock(spec=Orchestrator)
        mock_orc.run = AsyncMock()
        router_module.configure_orchestrator(mock_orc)
        app = FastAPI()
        app.include_router(router_module.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)

        # Capture total counter value across all labels before
        before_total: float = 0.0
        for stage in (
            "guardrails_pre",
            "opa_eval",
            "session_mgr",
            "llm_adapter",
            "guardrails_post",
        ):
            before_total += _sample(
                "aegis_orchestrator_errors_total",
                {"stage": stage, "agent_type": "finance"},
            )

        client.post("/api/v1/tasks", json={})

        after_total: float = 0.0
        for stage in (
            "guardrails_pre",
            "opa_eval",
            "session_mgr",
            "llm_adapter",
            "guardrails_post",
        ):
            after_total += _sample(
                "aegis_orchestrator_errors_total",
                {"stage": stage, "agent_type": "finance"},
            )

        assert (after_total - before_total) == pytest.approx(0.0)
