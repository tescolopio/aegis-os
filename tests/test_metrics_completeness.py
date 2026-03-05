"""tests/test_metrics_completeness.py — W1-3 regression: every orchestrator code path.

This file is added to CI as a required check.  It parametrises across **every**
documented error path in ``src/control_plane/orchestrator.py`` and asserts that
``aegis_orchestrator_errors_total{stage, agent_type}`` increments by exactly 1
for each path.  A missing increment means the error guard in that stage has been
removed or bypassed — which would be a silent metric drop.

Stage key values correspond to the ``stage_key`` argument passed to
``_span_stage()`` in the orchestrator (A1-1 canonical span names).

Covered scenarios
-----------------
1.  pre_pii_scrub      — PromptInjectionError from check_prompt_injection
2.  pre_pii_scrub      — RuntimeError from mask_pii (pre-sanitize)
3.  policy_eval        — OpaUnavailableError (OPA server down)
4.  policy_eval        — policy allow=False denial
5.  policy_eval        — policy action="reject" denial
6.  policy_mask        — RuntimeError during OPA-triggered field masking
7.  jit_token_issue    — JoseExpiredSignatureError from validate_token
8.  jit_token_issue    — is_expired() returns True (clock-skew guard)
9.  jit_token_issue    — agent_type mismatch (TokenScopeError)
10. watchdog_pre       — BudgetExceededError from check_budget
11. llm_invoke         — RuntimeError from adapter.complete
12. watchdog_record    — BudgetExceededError from record_spend
13. watchdog_loop      — LoopDetectedError (NO_PROGRESS streak)
14. watchdog_loop      — TokenVelocityError (velocity exceeded)
15. watchdog_loop      — PendingApprovalError (HUMAN_REQUIRED signal)
16. post_sanitize      — RuntimeError from mask_pii (post-sanitize)
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from jose.exceptions import ExpiredSignatureError as JoseExpiredSignatureError
from prometheus_client import REGISTRY

from src.adapters.base import BaseAdapter, LLMRequest, LLMResponse
from src.audit_vault.logger import AuditLogger
from src.control_plane.orchestrator import Orchestrator, OrchestratorRequest
from src.governance.guardrails import Guardrails, MaskResult, PromptInjectionError
from src.governance.policy_engine.opa_client import OpaUnavailableError, PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager
from src.watchdog.budget_enforcer import BudgetEnforcer
from src.watchdog.loop_detector import (
    LoopDetector,
    LoopSignal,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample(metric_name: str, labels: dict[str, str]) -> float:
    """Read a Prometheus sample from the global registry; return 0 if unseen."""
    value = REGISTRY.get_sample_value(metric_name, labels)
    return float(value) if value is not None else 0.0


_AGENT_TYPE = "finance"

_STUB_LLM = LLMResponse(
    content="stub",
    tokens_used=1,
    model="gpt-4o-mini",
    provider="stub",
    finish_reason="stop",
)


class _OkAdapter(BaseAdapter):
    @property
    def provider_name(self) -> str:  # noqa: D102
        return "stub"

    async def complete(self, request: LLMRequest) -> LLMResponse:  # noqa: D102
        return _STUB_LLM


def _ok_guardrails() -> Guardrails:
    g = MagicMock(spec=Guardrails)
    g.check_prompt_injection.return_value = None
    g.mask_pii.return_value = MaskResult(text="clean", found_types=[])
    g.scrub.return_value = MaskResult(text="clean", found_types=[])
    return g


def _ok_policy() -> PolicyEngine:
    pe = MagicMock(spec=PolicyEngine)

    async def _ev(*_a: Any, **_kw: Any) -> PolicyResult:
        return PolicyResult(allowed=True)

    pe.evaluate = _ev
    return pe


def _ok_sm() -> SessionManager:
    sm = MagicMock(spec=SessionManager)
    sm.issue_token.return_value = "jwt.stub.token"
    return sm


def _orc(**kw: Any) -> Orchestrator:
    return Orchestrator(
        adapter=kw.get("adapter", _OkAdapter()),
        guardrails=kw.get("guardrails", _ok_guardrails()),
        policy_engine=kw.get("policy_engine", _ok_policy()),
        session_mgr=kw.get("session_mgr", _ok_sm()),
        audit_logger=AuditLogger("completeness_test"),
        tracer=None,
        budget_enforcer=kw.get("budget_enforcer"),
        loop_detector=kw.get("loop_detector"),
    )


def _req(**kw: Any) -> OrchestratorRequest:
    base: dict[str, Any] = {
        "prompt": "quarterly earnings summary",
        "agent_type": _AGENT_TYPE,
        "requester_id": "completeness-tester",
        "model": "gpt-4o-mini",
    }
    base.update(kw)
    return OrchestratorRequest(**base)


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------


@dataclass
class _Scenario:
    """One orchestrator failure scenario."""

    id: str
    stage: str
    orc: Orchestrator
    request: OrchestratorRequest


def _make_scenarios() -> list[_Scenario]:  # noqa: PLR0912 — building test data
    scenarios: list[_Scenario] = []

    # 1 — guardrails_pre: PromptInjectionError
    g1 = _ok_guardrails()
    g1.check_prompt_injection.side_effect = PromptInjectionError("injected")
    scenarios.append(
        _Scenario("s01_guardrails_injection", "pre_pii_scrub", _orc(guardrails=g1), _req())
    )

    # 2 — guardrails_pre: RuntimeError from mask_pii (pre)
    g2 = _ok_guardrails()
    g2.check_prompt_injection.return_value = None
    g2.mask_pii.side_effect = RuntimeError("mask_pii broke")
    scenarios.append(
        _Scenario("s02_guardrails_pre_mask", "pre_pii_scrub", _orc(guardrails=g2), _req())
    )

    # 3 — opa_eval: OPA unavailable
    pe3 = MagicMock(spec=PolicyEngine)
    pe3.evaluate = AsyncMock(side_effect=OpaUnavailableError("down"))
    scenarios.append(
        _Scenario("s03_opa_unavailable", "policy_eval", _orc(policy_engine=pe3), _req())
    )

    # 4 — opa_eval: policy denied (allow=False)
    pe4 = MagicMock(spec=PolicyEngine)
    pe4.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=False, reasons=["insufficient permissions"])
    )
    scenarios.append(_Scenario("s04_opa_denied", "policy_eval", _orc(policy_engine=pe4), _req()))

    # 5 — opa_eval: policy action=reject
    pe5 = MagicMock(spec=PolicyEngine)
    pe5.evaluate = AsyncMock(return_value=PolicyResult(allowed=True, action="reject"))
    scenarios.append(_Scenario("s05_opa_reject", "policy_eval", _orc(policy_engine=pe5), _req()))

    # 6 — opa_mask: scrub raises during mask field processing
    pe6 = MagicMock(spec=PolicyEngine)
    pe6.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=True, action="mask", fields=["prompt"])
    )
    g6 = _ok_guardrails()
    g6.scrub.side_effect = RuntimeError("scrub failed")
    scenarios.append(
        _Scenario(
            "s06_opa_mask_scrub",
            "policy_mask",
            _orc(policy_engine=pe6, guardrails=g6),
            _req(),
        )
    )

    # 7 — session_mgr: expired token (JoseExpiredSignatureError)
    sm7 = _ok_sm()
    sm7.validate_token.side_effect = JoseExpiredSignatureError("expired")
    scenarios.append(
        _Scenario(
            "s07_session_expired_jose",
            "jit_token_issue",
            _orc(session_mgr=sm7),
            _req(session_token="fake.jwt.here"),
        )
    )

    # 8 — session_mgr: is_expired() guard returns True
    sm8 = _ok_sm()
    claims8 = MagicMock()
    claims8.agent_type = _AGENT_TYPE
    sm8.validate_token.return_value = claims8
    sm8.is_expired.return_value = True
    scenarios.append(
        _Scenario(
            "s08_session_expired_guard",
            "jit_token_issue",
            _orc(session_mgr=sm8),
            _req(session_token="fake.jwt.here"),
        )
    )

    # 9 — session_mgr: agent_type mismatch (TokenScopeError)
    sm9 = _ok_sm()
    claims9 = MagicMock()
    claims9.agent_type = "different_type"  # mismatches request.agent_type="finance"
    sm9.validate_token.return_value = claims9
    sm9.is_expired.return_value = False
    scenarios.append(
        _Scenario(
            "s09_session_scope",
            "jit_token_issue",
            _orc(session_mgr=sm9),
            _req(session_token="fake.jwt.here"),
        )
    )

    # 10 — watchdog_pre: budget already exhausted
    be10 = BudgetEnforcer()
    sid10 = uuid4()
    be10.create_session(sid10, agent_type=_AGENT_TYPE, budget_limit_usd=Decimal("0.000001"))
    try:
        be10.record_spend(sid10, Decimal("1.00"))
    except Exception:
        pass
    scenarios.append(
        _Scenario(
            "s10_watchdog_pre",
            "watchdog_pre",
            _orc(budget_enforcer=be10),
            _req(budget_session_id=sid10),
        )
    )

    # 11 — llm_adapter: adapter raises
    class _FailAdapter(BaseAdapter):
        @property
        def provider_name(self) -> str:  # noqa: D102
            return "fail_stub"

        async def complete(self, r: LLMRequest) -> LLMResponse:
            raise RuntimeError("provider down")

    scenarios.append(
        _Scenario("s11_llm_adapter", "llm_invoke", _orc(adapter=_FailAdapter()), _req())
    )

    # 12 — watchdog_record: over-budget after LLM response
    be12 = BudgetEnforcer()
    sid12 = uuid4()
    be12.create_session(sid12, agent_type=_AGENT_TYPE, budget_limit_usd=Decimal("0.000001"))
    scenarios.append(
        _Scenario(
            "s12_watchdog_record",
            "watchdog_record",
            _orc(budget_enforcer=be12),
            _req(budget_session_id=sid12),
        )
    )

    # 13 — watchdog_loop: LoopDetectedError (NO_PROGRESS streak)
    ld13 = LoopDetector(max_agent_steps=1)  # 1 consecutive NO_PROGRESS trips breaker
    sid13 = uuid4()
    ld13.create_context(sid13, agent_type=_AGENT_TYPE)
    scenarios.append(
        _Scenario(
            "s13_watchdog_loop_halt",
            "watchdog_loop",
            _orc(loop_detector=ld13),
            _req(
                loop_session_id=sid13,
                loop_signal=LoopSignal.NO_PROGRESS,
                loop_token_delta=1,
            ),
        )
    )

    # 14 — watchdog_loop: TokenVelocityError
    ld14 = LoopDetector(max_token_velocity=5)
    sid14 = uuid4()
    ld14.create_context(sid14, agent_type=_AGENT_TYPE)
    scenarios.append(
        _Scenario(
            "s14_watchdog_loop_velocity",
            "watchdog_loop",
            _orc(loop_detector=ld14),
            _req(
                loop_session_id=sid14,
                loop_signal=LoopSignal.PROGRESS,
                loop_token_delta=9999,  # vastly exceeds max_token_velocity=5
            ),
        )
    )

    # 15 — watchdog_loop: PendingApprovalError (HUMAN_REQUIRED)
    ld15 = LoopDetector()
    sid15 = uuid4()
    ld15.create_context(sid15, agent_type=_AGENT_TYPE)
    scenarios.append(
        _Scenario(
            "s15_watchdog_loop_approval",
            "watchdog_loop",
            _orc(loop_detector=ld15),
            _req(
                loop_session_id=sid15,
                loop_signal=LoopSignal.HUMAN_REQUIRED,
                loop_token_delta=1,
            ),
        )
    )

    # 16 — guardrails_post: mask_pii raises on second call (post-sanitize)
    # Use a list side_effect: first call (stage 1) returns normally,
    # second call (stage 5) raises RuntimeError.
    g16 = _ok_guardrails()
    g16.mask_pii.side_effect = [
        MaskResult(text="clean", found_types=[]),  # stage 1 pre-sanitize
        RuntimeError("post-sanitize error"),        # stage 5 post-sanitize
    ]
    scenarios.append(
        _Scenario(
            "s16_guardrails_post",
            "post_sanitize",
            _orc(guardrails=g16),
            _req(),
        )
    )

    return scenarios


_SCENARIOS = _make_scenarios()
_SCENARIO_IDS = [s.id for s in _SCENARIOS]


# ---------------------------------------------------------------------------
# Parametrized regression test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", _SCENARIOS, ids=_SCENARIO_IDS)
async def test_every_code_path_emits_error_counter(scenario: _Scenario) -> None:
    """Every orchestrator error path must increment aegis_orchestrator_errors_total.

    This is the primary regression guard against silent metric drops.  If a
    developer removes or moves an exception handler in orchestrator.py without
    updating the ``_stage_error_guard`` context manager, this test will fail for
    the affected stage.
    """
    before = _sample(
        "aegis_orchestrator_errors_total",
        {"stage": scenario.stage, "agent_type": _AGENT_TYPE},
    )

    with pytest.raises(Exception):
        await scenario.orc.run(scenario.request)

    after = _sample(
        "aegis_orchestrator_errors_total",
        {"stage": scenario.stage, "agent_type": _AGENT_TYPE},
    )

    assert (after - before) == pytest.approx(1.0), (
        f"Scenario {scenario.id!r}: expected aegis_orchestrator_errors_total"
        f"[stage={scenario.stage!r}, agent_type={_AGENT_TYPE!r}] to increment by 1 "
        f"(delta was {after - before:.0f})"
    )
