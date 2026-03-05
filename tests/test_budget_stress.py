"""W1-4 — Parameterised stress test: 500 sequential tasks.

Five agent types × 100 tasks each = 500 total.  Every task calls
:meth:`~src.watchdog.budget_enforcer.BudgetEnforcer.record_tokens` with a
seeded-random token count (1–1 000) and asserts all four W1-4 invariants:

1. **Zero budget overruns** — ``session.cost_usd ≤ session.budget_limit_usd``
   after every single task.
2. **Zero silent metric drops** — ``sum(aegis_tokens_consumed_total)`` delta
   equals the exact sum of all token counts for the agent-type run.
3. **No stub calls** — :meth:`~src.watchdog.budget_enforcer.BudgetEnforcer.record_spend`
   called exactly once per task with a non-zero :class:`~decimal.Decimal` amount.
4. **Performance gate** — each 100-task batch completes in < 12 s
   (5 × 12 s = 60 s total, satisfying the CI requirement).
"""

from __future__ import annotations

import random
import time
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import pytest
from prometheus_client import REGISTRY

from src.watchdog.budget_enforcer import BudgetEnforcer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AGENT_TYPES: list[str] = ["finance", "hr", "it", "legal", "general"]

#: Tasks per parametrized run; 5 × 100 = 500 total.
TASKS_PER_AGENT: int = 100

#: Fixed seed — makes every token sequence fully reproducible across CI runs.
_SEED: int = 42

_MIN_TOKENS: int = 1
_MAX_TOKENS: int = 1_000

# Worst-case spend per agent: 100 × 1 000 tokens × $0.000002 = $0.20.
# $5.00 leaves > 25 × headroom so BudgetExceededError is never raised.
_BUDGET_LIMIT: Decimal = Decimal("5.00")

# 12 s per 100-task batch → 5 × 12 s = 60 s total.
_MAX_SECONDS_PER_AGENT: float = 12.0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _counter_sample(agent_type: str) -> float:
    """Return the current value of ``aegis_tokens_consumed_total{agent_type}``."""
    value = REGISTRY.get_sample_value(
        "aegis_tokens_consumed_total", {"agent_type": agent_type}
    )
    return float(value) if value is not None else 0.0


# ---------------------------------------------------------------------------
# Stress test (parametrized over all five agent types)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("agent_type", AGENT_TYPES)
def test_stress_100_tasks(agent_type: str) -> None:
    """Run 100 sequential token-debit tasks and assert all four W1-4 invariants.

    Each parametrised run is isolated: it creates a fresh
    :class:`~src.watchdog.budget_enforcer.BudgetEnforcer` instance and a brand-
    new session UUID so there is no shared mutable state between agent types.

    Parameters
    ----------
    agent_type:
        One of the five canonical agent types.  Supplied via
        ``@pytest.mark.parametrize``.
    """
    # ----------------------------------------------------------------
    # Reproducible token sequence
    # ----------------------------------------------------------------
    rng = random.Random(_SEED)
    token_counts: list[int] = [
        rng.randint(_MIN_TOKENS, _MAX_TOKENS) for _ in range(TASKS_PER_AGENT)
    ]

    # ----------------------------------------------------------------
    # Fresh session — budget large enough that it is never exhausted
    # ----------------------------------------------------------------
    enforcer = BudgetEnforcer()
    sid = uuid4()
    enforcer.create_session(sid, agent_type=agent_type, budget_limit_usd=_BUDGET_LIMIT)

    # Snapshot the Prometheus counter before any tokens are recorded.
    # Using a per-agent-type label means each run is independent in the registry.
    before_counter: float = _counter_sample(agent_type)

    # ----------------------------------------------------------------
    # Spy on record_spend to satisfy Invariant 3 without disabling it.
    # patch.object adds the mock to the *instance* dictionary, shadowing
    # the class method; the wraps=... argument ensures the original
    # implementation still executes (budget bookkeeping is preserved).
    # ----------------------------------------------------------------
    with patch.object(enforcer, "record_spend", wraps=enforcer.record_spend) as mock_spend:
        start: float = time.perf_counter()

        for task_idx, tokens in enumerate(token_counts):
            enforcer.record_tokens(sid, tokens)

            # Invariant 1 — zero budget overruns: checked inline after every task.
            session = enforcer.get_session(sid)
            assert session is not None, f"Session disappeared at task {task_idx}"
            assert session.cost_usd <= session.budget_limit_usd, (
                f"Budget overrun at task {task_idx} (agent_type={agent_type!r}, "
                f"tokens={tokens}): cost={session.cost_usd!r} > "
                f"limit={session.budget_limit_usd!r}"
            )

        elapsed: float = time.perf_counter() - start

    # ----------------------------------------------------------------
    # Invariant 4 — performance gate
    # ----------------------------------------------------------------
    assert elapsed < _MAX_SECONDS_PER_AGENT, (
        f"Performance gate failed for agent_type={agent_type!r}: "
        f"{elapsed:.3f}s ≥ {_MAX_SECONDS_PER_AGENT}s for {TASKS_PER_AGENT} tasks"
    )

    # ----------------------------------------------------------------
    # Invariant 3 — no stub calls
    # record_spend must fire once per task and each call must carry a
    # strictly positive Decimal amount.  A zero or missing amount
    # indicates a no-op stub is in the hot path.
    # ----------------------------------------------------------------
    assert mock_spend.call_count == TASKS_PER_AGENT, (
        f"record_spend call count mismatch for agent_type={agent_type!r}: "
        f"expected {TASKS_PER_AGENT}, got {mock_spend.call_count}"
    )
    for i, call_args in enumerate(mock_spend.call_args_list):
        # record_spend(session_id, amount_usd) — second positional arg is amount
        amount_usd: Decimal = call_args.args[1]
        assert amount_usd > Decimal("0"), (
            f"Task {i} (agent_type={agent_type!r}): record_spend received "
            f"zero or negative amount {amount_usd!r} — indicates a stub or "
            f"no-op implementation"
        )

    # ----------------------------------------------------------------
    # Invariant 2 — zero silent metric drops
    # The counter delta must equal the exact sum of all recorded token counts.
    # Any discrepancy means at least one record_tokens call failed to
    # reach the Prometheus increment.
    # ----------------------------------------------------------------
    after_counter: float = _counter_sample(agent_type)
    delta: float = after_counter - before_counter
    expected_total: float = float(sum(token_counts))

    assert delta == pytest.approx(expected_total), (
        f"Silent metric drop detected for agent_type={agent_type!r}: "
        f"counter delta={delta:.0f}, expected={expected_total:.0f} "
        f"(difference={abs(delta - expected_total):.0f} tokens unaccounted for)"
    )
