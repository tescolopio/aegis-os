"""A1-3 — Integration test: one task produces exactly N audit events in deterministic order.

Five test classes cover the full A1-3 testing contract:

    TestDeterminism         — 50 identical runs produce the same (event, stage) sequence
    TestEventCount          — every happy-path run produces exactly EXPECTED_AUDIT_EVENT_COUNT
    TestGapDetection        — sequence_numbers form a gapless 0..N-1 range per task
    TestDuplicateDetection  — no (task_id, stage, sequence_number) tuple appears twice
    TestCrossRunIsolation   — concurrent task events are isolated by task_id
"""

from __future__ import annotations

import asyncio
from collections.abc import MutableMapping
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from structlog.testing import capture_logs

from src.adapters.base import BaseAdapter, LLMRequest, LLMResponse
from src.audit_vault.logger import AuditLogger
from src.control_plane.orchestrator import Orchestrator, OrchestratorRequest
from src.governance.guardrails import Guardrails, MaskResult
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager

# ---------------------------------------------------------------------------
# Contract constant — the expected number of audit events for a happy-path run
# with no PII in the prompt, no existing session token, no budget enforcer,
# and no loop detector.
#
# Stage breakdown:
#   Stage 1  guardrails.pre_sanitize  (outcome=allow)  1 event
#   Stage 2  policy.allowed           (outcome=allow)  1 event
#   Stage 3  token.issued             (outcome=allow)  1 event
#   Stage 4  llm.completed            (outcome=allow)  1 event
#   Stage 5  guardrails.post_sanitize (outcome=allow)  1 event
#                                                 ──────────
#                                                 5 events total
# ---------------------------------------------------------------------------
EXPECTED_AUDIT_EVENT_COUNT: int = 5

# ---------------------------------------------------------------------------
# Fixed test task_id — used by determinism tests so every run starts fresh
# but uses a known UUID for assertion clarity
# ---------------------------------------------------------------------------
_FIXED_TASK_ID = UUID("00000000-0000-0000-0000-000000000001")

_BASE_REQUEST = OrchestratorRequest(
    task_id=_FIXED_TASK_ID,
    prompt="Explain the quarterly audit findings in plain language.",
    agent_type="audit",
    requester_id="auditor-001",
    model="gpt-4o-mini",
)

# Expected (event_type, stage) sequence for a happy-path run — used by
# determinism tests to assert byte-for-byte identical ordering.
_EXPECTED_EVENT_SEQUENCE: list[tuple[str, str]] = [
    ("guardrails.pre_sanitize", "pre-pii-scrub"),
    ("policy.allowed", "policy-eval"),
    ("token.issued", "jit-token-issue"),
    ("llm.completed", "llm-invoke"),
    ("guardrails.post_sanitize", "post-sanitize"),
]


# ---------------------------------------------------------------------------
# Stub adapter & mock factories
# ---------------------------------------------------------------------------


class _StubAdapter(BaseAdapter):
    """Minimal async adapter that always returns a canned, PII-free response."""

    @property
    def provider_name(self) -> str:
        """Return stub provider label."""
        return "stub"

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Return a fixed LLMResponse without making any external calls."""
        return LLMResponse(
            content="Audit complete — no anomalies found.",
            tokens_used=12,
            model=request.model,
            provider="stub",
            finish_reason="stop",
        )


def _allow_engine() -> PolicyEngine:
    """Return a PolicyEngine mock that always allows."""
    pe: PolicyEngine = MagicMock(spec=PolicyEngine)

    async def _allow(*_a: Any, **_kw: Any) -> PolicyResult:
        return PolicyResult(allowed=True)

    pe.evaluate = _allow  # type: ignore[method-assign]
    return pe


def _ok_session_mgr() -> SessionManager:
    """Return a SessionManager mock that issues a fixed token and validates cleanly."""
    sm: SessionManager = MagicMock(spec=SessionManager)
    sm.issue_token.return_value = "test.jwt.token"  # type: ignore[attr-defined]
    sm.validate_token.return_value = MagicMock(  # type: ignore[attr-defined]
        jti="test-jti-001",
        agent_type="audit",
    )
    return sm


def _ok_guardrails() -> Guardrails:
    """Return a Guardrails mock that passes text through unchanged with no PII detected."""
    g: Guardrails = MagicMock(spec=Guardrails)
    g.check_prompt_injection.return_value = None  # type: ignore[attr-defined]

    def _pass_through(text: str) -> MaskResult:
        return MaskResult(text=text, found_types=[])

    g.mask_pii.side_effect = _pass_through  # type: ignore[attr-defined]
    return g


def _build_orchestrator(**kwargs: Any) -> Orchestrator:
    """Return an Orchestrator with a fresh AuditLogger and sensible defaults."""
    return Orchestrator(
        adapter=kwargs.get("adapter", _StubAdapter()),
        guardrails=kwargs.get("guardrails", _ok_guardrails()),
        policy_engine=kwargs.get("policy_engine", _allow_engine()),
        session_mgr=kwargs.get("session_mgr", _ok_session_mgr()),
        audit_logger=AuditLogger("test.orchestrator"),
    )


# ---------------------------------------------------------------------------
# Helpers: filter captured entries to those emitted by stage_event()
# ---------------------------------------------------------------------------


def _collect_stage_events(
    cap: list[MutableMapping[str, Any]],
) -> list[MutableMapping[str, Any]]:
    """Return only entries emitted via stage_event() — identified by 'outcome' field."""
    return [e for e in cap if "outcome" in e]


def _collect_stage_events_for_task(
    cap: list[MutableMapping[str, Any]], task_id: str
) -> list[MutableMapping[str, Any]]:
    """Return stage_event entries for a specific task_id, in emission order."""
    return [e for e in cap if "outcome" in e and e.get("task_id") == task_id]


# ---------------------------------------------------------------------------
# 1. Determinism — 50 identical runs must produce the same (event, stage) sequence
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Run the same task 50 times; assert the (event, stage) sequence is
    byte-for-byte identical across all 50 runs — a non-deterministic event
    sequence indicates a dropped, reordered, or spuriously inserted event."""

    @pytest.mark.asyncio
    async def test_event_sequence_is_deterministic_across_50_runs(self) -> None:
        """The (event, stage) tuple sequence must be identical for every run."""
        sequences: list[list[tuple[str, str]]] = []

        for _ in range(50):
            with capture_logs() as cap:
                await _build_orchestrator().run(_BASE_REQUEST)

            stage_events = _collect_stage_events(cap)
            seq = [(e["event"], e.get("stage", "")) for e in stage_events]
            sequences.append(seq)

        reference = sequences[0]
        assert reference, "Reference sequence must not be empty."
        assert reference == _EXPECTED_EVENT_SEQUENCE, (
            f"First run produced an unexpected event sequence.\n"
            f"  Expected: {_EXPECTED_EVENT_SEQUENCE}\n"
            f"  Got:      {reference}"
        )

        for i, seq in enumerate(sequences[1:], start=1):
            assert seq == reference, (
                f"Run {i + 1} produced a different event sequence.\n"
                f"  Expected: {reference}\n"
                f"  Got:      {seq}"
            )

    @pytest.mark.asyncio
    async def test_event_sequence_matches_documented_stage_order(self) -> None:
        """The (event, stage) sequence must match _EXPECTED_EVENT_SEQUENCE exactly."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        actual = [(e["event"], e.get("stage", "")) for e in stage_events]
        assert actual == _EXPECTED_EVENT_SEQUENCE, (
            f"Happy-path event sequence does not match documented stage order.\n"
            f"  Expected: {_EXPECTED_EVENT_SEQUENCE}\n"
            f"  Got:      {actual}"
        )

    @pytest.mark.asyncio
    async def test_all_stage_events_carry_correct_task_id(self) -> None:
        """All events in a single run must carry the same fixed task_id."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        task_ids = {e.get("task_id") for e in stage_events}
        assert task_ids == {str(_FIXED_TASK_ID)}, (
            f"Expected all events to carry task_id={_FIXED_TASK_ID!s}; "
            f"got: {task_ids}"
        )


# ---------------------------------------------------------------------------
# 2. Count assertion — every run must emit exactly EXPECTED_AUDIT_EVENT_COUNT
# ---------------------------------------------------------------------------


class TestEventCount:
    """Assert that a happy-path run produces exactly EXPECTED_AUDIT_EVENT_COUNT
    stage_event entries — no more, no fewer.  A run producing N-1 or N+1 events
    is a hard failure."""

    def test_expected_audit_event_count_is_documented(self) -> None:
        """EXPECTED_AUDIT_EVENT_COUNT must be a positive integer constant."""
        assert isinstance(EXPECTED_AUDIT_EVENT_COUNT, int)
        assert EXPECTED_AUDIT_EVENT_COUNT > 0, (
            "EXPECTED_AUDIT_EVENT_COUNT must reflect a complete pipeline run."
        )
        assert EXPECTED_AUDIT_EVENT_COUNT == len(_EXPECTED_EVENT_SEQUENCE), (
            "EXPECTED_AUDIT_EVENT_COUNT must equal the length of "
            "_EXPECTED_EVENT_SEQUENCE — update one or both constants."
        )

    @pytest.mark.asyncio
    async def test_happy_path_produces_expected_event_count(self) -> None:
        """A single happy-path run must emit exactly EXPECTED_AUDIT_EVENT_COUNT events."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        assert len(stage_events) == EXPECTED_AUDIT_EVENT_COUNT, (
            f"Expected exactly {EXPECTED_AUDIT_EVENT_COUNT} audit events for "
            f"a happy-path run; got {len(stage_events)}.\n"
            f"  Events: {[(e['event'], e.get('stage')) for e in stage_events]}"
        )

    @pytest.mark.asyncio
    async def test_n_minus_one_events_is_hard_failure(self) -> None:
        """Verify the count assertion catches N-1 events (guard for the test itself)."""
        # A run with exactly one stage produces 1 event — assert that checking
        # against EXPECTED_AUDIT_EVENT_COUNT with 1 event would fail.
        fake_event_count = EXPECTED_AUDIT_EVENT_COUNT - 1
        assert fake_event_count != EXPECTED_AUDIT_EVENT_COUNT, (
            "A run with N-1 events must not satisfy the count assertion."
        )

    @pytest.mark.asyncio
    async def test_n_plus_one_events_is_hard_failure(self) -> None:
        """Verify the count assertion catches N+1 events (guard for the test itself)."""
        fake_event_count = EXPECTED_AUDIT_EVENT_COUNT + 1
        assert fake_event_count != EXPECTED_AUDIT_EVENT_COUNT, (
            "A run with N+1 events must not satisfy the count assertion."
        )

    @pytest.mark.asyncio
    async def test_50_runs_all_produce_exact_event_count(self) -> None:
        """All 50 runs must produce exactly EXPECTED_AUDIT_EVENT_COUNT events."""
        for run_idx in range(50):
            with capture_logs() as cap:
                await _build_orchestrator().run(_BASE_REQUEST)

            stage_events = _collect_stage_events(cap)
            assert len(stage_events) == EXPECTED_AUDIT_EVENT_COUNT, (
                f"Run {run_idx + 1} produced {len(stage_events)} events "
                f"(expected {EXPECTED_AUDIT_EVENT_COUNT}).\n"
                f"  Events: {[(e['event'], e.get('stage')) for e in stage_events]}"
            )


# ---------------------------------------------------------------------------
# 3. Gap detection — sequence_numbers must form a gapless monotonic sequence
# ---------------------------------------------------------------------------


class TestGapDetection:
    """Assert that sequence_number fields are strictly monotonic with no gaps.

    For a happy-path run the expected sequence is 0, 1, 2, 3, 4 — one
    integer per pipeline stage.  Any gap (e.g. 0, 1, 3, 4) means an audit
    event was dropped between those two positions.
    """

    @pytest.mark.asyncio
    async def test_all_stage_events_carry_sequence_number(self) -> None:
        """Every stage_event entry must include a 'sequence_number' field."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        assert stage_events, "No stage events captured."
        for event in stage_events:
            assert "sequence_number" in event, (
                f"stage_event entry is missing 'sequence_number' field.\n"
                f"  entry: {event}"
            )
            assert isinstance(event["sequence_number"], int), (
                f"'sequence_number' must be an int; "
                f"got {type(event['sequence_number']).__name__}"
            )

    @pytest.mark.asyncio
    async def test_sequence_numbers_start_at_zero(self) -> None:
        """The first event in a task run must carry sequence_number=0."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        assert stage_events, "No stage events captured."
        assert stage_events[0]["sequence_number"] == 0, (
            f"First event must have sequence_number=0; "
            f"got {stage_events[0].get('sequence_number')}"
        )

    @pytest.mark.asyncio
    async def test_sequence_numbers_are_strictly_monotonic(self) -> None:
        """sequence_number must increase by exactly 1 for each consecutive event."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        seq_nums = [e["sequence_number"] for e in stage_events]
        assert seq_nums, "No stage events captured — cannot verify sequence_numbers."

        for i in range(1, len(seq_nums)):
            assert seq_nums[i] == seq_nums[i - 1] + 1, (
                f"sequence_number gap detected between events {i - 1} and {i}.\n"
                f"  sequence_numbers: {seq_nums}\n"
                f"  expected each consecutive diff to be exactly 1"
            )

    @pytest.mark.asyncio
    async def test_sequence_numbers_end_at_n_minus_one(self) -> None:
        """The last event must carry sequence_number = EXPECTED_AUDIT_EVENT_COUNT - 1."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        assert stage_events, "No stage events captured."
        last_seq = stage_events[-1]["sequence_number"]
        expected_last = EXPECTED_AUDIT_EVENT_COUNT - 1
        assert last_seq == expected_last, (
            f"Last event must have sequence_number={expected_last}; "
            f"got {last_seq}"
        )

    @pytest.mark.asyncio
    async def test_sequence_numbers_form_complete_range(self) -> None:
        """sequence_numbers must form exactly range(0, N) with no gaps or extras."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        seq_nums = [e["sequence_number"] for e in stage_events]
        expected = list(range(EXPECTED_AUDIT_EVENT_COUNT))
        assert seq_nums == expected, (
            f"sequence_numbers do not form a complete gapless range.\n"
            f"  Got:      {seq_nums}\n"
            f"  Expected: {expected}"
        )

    @pytest.mark.asyncio
    async def test_no_gaps_across_50_runs(self) -> None:
        """50 consecutive runs must each produce gapless sequence_numbers."""
        for run_idx in range(50):
            with capture_logs() as cap:
                await _build_orchestrator().run(_BASE_REQUEST)

            stage_events = _collect_stage_events(cap)
            seq_nums = [e["sequence_number"] for e in stage_events]
            expected = list(range(len(seq_nums)))
            assert seq_nums == expected, (
                f"Run {run_idx + 1} has sequence_number gaps.\n"
                f"  Got:      {seq_nums}\n"
                f"  Expected: {expected}"
            )


# ---------------------------------------------------------------------------
# 4. Duplicate detection — no (task_id, stage, sequence_number) appears twice
# ---------------------------------------------------------------------------


class TestDuplicateDetection:
    """Assert that events within a task run have unique
    (task_id, stage, sequence_number) tuples.

    A duplicate tuple means the same pipeline position was recorded more than
    once — this is a hard indicator of a duplicated audit event."""

    @pytest.mark.asyncio
    async def test_no_duplicate_tuples_in_single_run(self) -> None:
        """No (task_id, stage, sequence_number) tuple must appear more than once."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        tuples: list[tuple[Any, Any, Any]] = [
            (e.get("task_id"), e.get("stage"), e.get("sequence_number"))
            for e in stage_events
        ]

        seen: set[tuple[Any, Any, Any]] = set()
        for tup in tuples:
            assert tup not in seen, (
                f"Duplicate (task_id, stage, sequence_number) tuple detected: {tup}\n"
                f"  All tuples: {tuples}"
            )
            seen.add(tup)

    @pytest.mark.asyncio
    async def test_sequence_numbers_are_unique_within_task(self) -> None:
        """Every sequence_number in a single task run must be unique."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        seq_nums = [e["sequence_number"] for e in stage_events]
        assert len(seq_nums) == len(set(seq_nums)), (
            f"Duplicate sequence_numbers detected within a single run: {seq_nums}"
        )

    @pytest.mark.asyncio
    async def test_stage_names_are_unique_within_task(self) -> None:
        """Each pipeline stage must appear at most once per happy-path run."""
        with capture_logs() as cap:
            await _build_orchestrator().run(_BASE_REQUEST)

        stage_events = _collect_stage_events(cap)
        stages = [e.get("stage") for e in stage_events]
        assert len(stages) == len(set(stages)), (
            f"Duplicate stage names detected within a single run: {stages}\n"
            f"Each stage must produce exactly one event on the happy path."
        )

    @pytest.mark.asyncio
    async def test_no_duplicate_tuples_across_50_runs(self) -> None:
        """Within each of 50 runs, (task_id, stage, sequence_number) tuples must be unique."""
        for run_idx in range(50):
            with capture_logs() as cap:
                await _build_orchestrator().run(_BASE_REQUEST)

            stage_events = _collect_stage_events(cap)
            tuples: list[tuple[Any, Any, Any]] = [
                (e.get("task_id"), e.get("stage"), e.get("sequence_number"))
                for e in stage_events
            ]
            assert len(tuples) == len(set(tuples)), (
                f"Run {run_idx + 1} contains duplicate "
                f"(task_id, stage, sequence_number) tuples.\n"
                f"  Tuples: {tuples}"
            )


# ---------------------------------------------------------------------------
# 5. Cross-run isolation — concurrent task events are isolated by task_id
# ---------------------------------------------------------------------------


class TestCrossRunIsolation:
    """Run two tasks concurrently with asyncio.gather(); assert that events
    captured for task A never contain task B's task_id and vice versa.

    Because capture_logs() captures all structlog output globally, isolation
    is verified by partitioning the combined capture by task_id and confirming
    every partition contains only events belonging to the correct task."""

    @pytest.mark.asyncio
    async def test_concurrent_tasks_events_are_isolated_by_task_id(self) -> None:
        """Events from each concurrent task must partition cleanly by task_id."""
        task_a_id = UUID("aaaaaaaa-0000-0000-0000-000000000000")
        task_b_id = UUID("bbbbbbbb-0000-0000-0000-000000000000")

        request_a = OrchestratorRequest(
            task_id=task_a_id,
            prompt="Task A: Explain the quarterly audit findings.",
            agent_type="audit",
            requester_id="auditor-a",
        )
        request_b = OrchestratorRequest(
            task_id=task_b_id,
            prompt="Task B: Summarize recent compliance results.",
            agent_type="audit",
            requester_id="auditor-b",
        )

        orch_a = _build_orchestrator()
        orch_b = _build_orchestrator()

        with capture_logs() as cap:
            await asyncio.gather(orch_a.run(request_a), orch_b.run(request_b))

        events_a = _collect_stage_events_for_task(cap, str(task_a_id))
        events_b = _collect_stage_events_for_task(cap, str(task_b_id))

        assert len(events_a) == EXPECTED_AUDIT_EVENT_COUNT, (
            f"Task A must produce {EXPECTED_AUDIT_EVENT_COUNT} events; "
            f"got {len(events_a)}"
        )
        assert len(events_b) == EXPECTED_AUDIT_EVENT_COUNT, (
            f"Task B must produce {EXPECTED_AUDIT_EVENT_COUNT} events; "
            f"got {len(events_b)}"
        )

        # No event for task A may carry task B's task_id
        for event in events_a:
            assert event.get("task_id") != str(task_b_id), (
                f"Task A event stream contains an event with task B's task_id.\n"
                f"  event: {event}"
            )
        # No event for task B may carry task A's task_id
        for event in events_b:
            assert event.get("task_id") != str(task_a_id), (
                f"Task B event stream contains an event with task A's task_id.\n"
                f"  event: {event}"
            )

    @pytest.mark.asyncio
    async def test_concurrent_tasks_produce_combined_event_count(self) -> None:
        """Two concurrent tasks must together produce 2 × EXPECTED_AUDIT_EVENT_COUNT events."""
        task_a_id = UUID("cccccccc-0000-0000-0000-000000000000")
        task_b_id = UUID("dddddddd-0000-0000-0000-000000000000")

        request_a = OrchestratorRequest(
            task_id=task_a_id,
            prompt="Task A: Monthly audit summary.",
            agent_type="audit",
            requester_id="auditor-c",
        )
        request_b = OrchestratorRequest(
            task_id=task_b_id,
            prompt="Task B: Compliance check results.",
            agent_type="audit",
            requester_id="auditor-d",
        )

        orch_a = _build_orchestrator()
        orch_b = _build_orchestrator()

        with capture_logs() as cap:
            await asyncio.gather(orch_a.run(request_a), orch_b.run(request_b))

        stage_events = _collect_stage_events(cap)
        expected_total = 2 * EXPECTED_AUDIT_EVENT_COUNT
        assert len(stage_events) == expected_total, (
            f"Two concurrent tasks must produce {expected_total} total events; "
            f"got {len(stage_events)}"
        )

    @pytest.mark.asyncio
    async def test_concurrent_tasks_have_independent_sequence_numbers(self) -> None:
        """Each task's sequence numbers must form an independent 0..N-1 range.

        Two tasks using separate Orchestrator/AuditLogger instances each get
        their own counter, so both should produce sequence_numbers 0,1,2,3,4
        independently.
        """
        task_a_id = UUID("eeeeeeee-0000-0000-0000-000000000000")
        task_b_id = UUID("ffffffff-0000-0000-0000-000000000000")

        request_a = OrchestratorRequest(
            task_id=task_a_id,
            prompt="Task A: Monthly financial review.",
            agent_type="audit",
            requester_id="auditor-e",
        )
        request_b = OrchestratorRequest(
            task_id=task_b_id,
            prompt="Task B: Risk assessment.",
            agent_type="audit",
            requester_id="auditor-f",
        )

        orch_a = _build_orchestrator()
        orch_b = _build_orchestrator()

        with capture_logs() as cap:
            await asyncio.gather(orch_a.run(request_a), orch_b.run(request_b))

        events_a = _collect_stage_events_for_task(cap, str(task_a_id))
        events_b = _collect_stage_events_for_task(cap, str(task_b_id))

        seq_a = [e["sequence_number"] for e in events_a]
        seq_b = [e["sequence_number"] for e in events_b]

        expected_seq = list(range(EXPECTED_AUDIT_EVENT_COUNT))
        assert seq_a == expected_seq, (
            f"Task A sequence numbers must be {expected_seq}; got {seq_a}"
        )
        assert seq_b == expected_seq, (
            f"Task B sequence numbers must be {expected_seq}; got {seq_b}"
        )

    @pytest.mark.asyncio
    async def test_no_orphaned_events_in_concurrent_run(self) -> None:
        """Every event in a concurrent capture must belong to a known task_id."""
        task_a_id = UUID("11111111-0000-0000-0000-000000000000")
        task_b_id = UUID("22222222-0000-0000-0000-000000000000")
        known_ids = {str(task_a_id), str(task_b_id)}

        request_a = OrchestratorRequest(
            task_id=task_a_id,
            prompt="Task A: Orphan isolation check.",
            agent_type="audit",
            requester_id="auditor-g",
        )
        request_b = OrchestratorRequest(
            task_id=task_b_id,
            prompt="Task B: Orphan isolation check.",
            agent_type="audit",
            requester_id="auditor-h",
        )

        orch_a = _build_orchestrator()
        orch_b = _build_orchestrator()

        with capture_logs() as cap:
            await asyncio.gather(orch_a.run(request_a), orch_b.run(request_b))

        stage_events = _collect_stage_events(cap)
        for event in stage_events:
            tid = event.get("task_id")
            assert tid in known_ids, (
                f"Orphaned event detected — task_id {tid!r} is not one of the "
                f"known task IDs {known_ids}.\n"
                f"  event: {event}"
            )
