"""P1-3 tests: task_id is mandatory and propagates through every pipeline layer.

Four test categories (per the P1-3 roadmap requirements):

1. Unit — auto-generation
   Omit task_id from the request; assert the orchestrator auto-generates a
   valid UUID v4 and reflects it in the returned OrchestratorResult.

2. Unit — thread-through
   Supply a fixed task_id; assert the same UUID value appears in every OTel
   span attribute, every AuditLogger event, and every budget-related audit
   record produced by that run.

3. Negative — MissingTaskIdError guard
   Bypass Pydantic validation with model_construct to create a request with
   task_id=None; assert MissingTaskIdError is raised *before* the LLM
   adapter's complete() method is ever called.

4. Concurrency — zero cross-contamination
   Run 20 concurrent tasks with distinct task_id values; assert that every
   AuditLogger event records one of the 20 expected task_ids (no bleed-
   through from other coroutines).
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from src.adapters.base import BaseAdapter, LLMRequest, LLMResponse
from src.audit_vault.logger import AuditLogger
from src.control_plane.orchestrator import (
    MissingTaskIdError,
    Orchestrator,
    OrchestratorRequest,
    OrchestratorResult,
)
from src.governance.guardrails import Guardrails
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager
from src.watchdog.budget_enforcer import BudgetEnforcer

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------


class _StubAdapter(BaseAdapter):
    """Minimal adapter that returns a deterministic canned response."""

    @property
    def provider_name(self) -> str:  # noqa: D102
        return "stub"

    async def complete(self, request: LLMRequest) -> LLMResponse:  # noqa: D102
        return LLMResponse(
            content="stub response",
            tokens_used=10,
            model=request.model,
            provider="stub",
            finish_reason="stop",
        )


class RecordingAuditLogger(AuditLogger):
    """AuditLogger that stores every emitted event for later assertion.

    All ``info``, ``warning``, and ``error`` calls are captured with their
    keyword arguments in ``self.events``.
    """

    def __init__(self) -> None:
        super().__init__("test.recording")
        self.events: list[dict[str, object]] = []

    def _record(self, level: str, event: str, **kwargs: object) -> None:
        self.events.append({"level": level, "event": event, **kwargs})

    def info(self, event: str, **kwargs: object) -> None:
        self._record("info", event, **kwargs)
        super().info(event, **kwargs)

    def warning(self, event: str, **kwargs: object) -> None:
        self._record("warning", event, **kwargs)
        super().warning(event, **kwargs)

    def error(self, event: str, **kwargs: object) -> None:
        self._record("error", event, **kwargs)
        super().error(event, **kwargs)


def _mock_policy_engine(allowed: bool = True) -> PolicyEngine:
    """Return a PolicyEngine stub that always allows (or denies)."""
    engine = MagicMock(spec=PolicyEngine)
    engine.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=allowed, reasons=[], action="allow", fields=[])
    )
    return engine


def _make_orchestrator(
    *,
    audit_logger: AuditLogger | None = None,
    tracer: Any = None,
    budget_enforcer: BudgetEnforcer | None = None,
) -> Orchestrator:
    return Orchestrator(
        adapter=_StubAdapter(),
        guardrails=Guardrails(),
        policy_engine=_mock_policy_engine(),
        session_mgr=SessionManager(),
        audit_logger=audit_logger,
        tracer=tracer,
        budget_enforcer=budget_enforcer,
    )


def _install_otel_exporter() -> tuple[InMemorySpanExporter, Any]:
    """Create an isolated TracerProvider + exporter pair for span assertions."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test.p1_3")
    return exporter, tracer


def _base_request(**kwargs: Any) -> OrchestratorRequest:
    defaults: dict[str, Any] = {
        "prompt": "What is the capital of France?",
        "agent_type": "general",
        "requester_id": "tester-001",
    }
    defaults.update(kwargs)
    return OrchestratorRequest(**defaults)


# ---------------------------------------------------------------------------
# 1. Unit — auto-generation
# ---------------------------------------------------------------------------


class TestTaskIdGeneration:
    """Orchestrator auto-generates a UUID v4 when task_id is omitted."""

    @pytest.fixture()
    def orc(self) -> Orchestrator:
        return _make_orchestrator()

    @pytest.mark.asyncio
    async def test_auto_generates_uuid_when_task_id_omitted(self, orc: Orchestrator) -> None:
        """A request without an explicit task_id produces a non-None result.task_id."""
        req = OrchestratorRequest(
            prompt="Hello",
            agent_type="general",
            requester_id="user-001",
        )
        # task_id was not supplied — Pydantic populates it via default_factory
        assert req.task_id is not None, "OrchestratorRequest must auto-generate task_id"

        result = await orc.run(req)
        assert isinstance(result.task_id, UUID), (
            "result.task_id must be a UUID; got {type(result.task_id)}"
        )

    @pytest.mark.asyncio
    async def test_auto_generated_task_id_is_uuid4_format(self, orc: Orchestrator) -> None:
        """The auto-generated task_id must be a valid UUID (version 4)."""
        req = _base_request()
        result = await orc.run(req)
        # UUID v4: version bits must be 4
        assert result.task_id.version == 4

    @pytest.mark.asyncio
    async def test_preserves_caller_supplied_task_id(self, orc: Orchestrator) -> None:
        """When the caller supplies task_id, the result carries back the same value."""
        fixed_id = uuid4()
        result = await orc.run(_base_request(task_id=fixed_id))
        assert result.task_id == fixed_id, (
            f"Expected result.task_id={fixed_id}, got {result.task_id}"
        )

    @pytest.mark.asyncio
    async def test_two_auto_generated_task_ids_are_unique(self, orc: Orchestrator) -> None:
        """Each call auto-generates a distinct task_id — UUIDs must never collide."""
        r1 = await orc.run(_base_request())
        r2 = await orc.run(_base_request())
        assert r1.task_id != r2.task_id


# ---------------------------------------------------------------------------
# 2. Unit — thread-through
# ---------------------------------------------------------------------------


class TestTaskIdThreadThrough:
    """A fixed task_id appears verbatim in spans, audit events, and budget records."""

    def _setup(self) -> tuple[UUID, OrchestratorResult, InMemorySpanExporter, RecordingAuditLogger]:
        """Synchronous fixture helper — returns coroutine; callers must await."""
        raise NotImplementedError("use _make_result() instead")

    @pytest.mark.asyncio
    async def test_task_id_on_root_otel_span(self) -> None:
        """orchestrator.run span carries task_id as an attribute."""
        fixed_id = uuid4()
        exporter, tracer = _install_otel_exporter()
        orc = _make_orchestrator(tracer=tracer)

        await orc.run(_base_request(task_id=fixed_id))

        span_names = {s.name: s for s in exporter.get_finished_spans()}
        root = span_names.get("orchestrator.run")
        assert root is not None, "orchestrator.run span not found"
        assert root.attributes.get("task_id") == str(fixed_id), (
            f"Expected task_id={fixed_id!s} on root span; "
            f"got {root.attributes.get('task_id')!r}"
        )

    @pytest.mark.asyncio
    async def test_task_id_on_all_stage_spans(self) -> None:
        """Every named stage span carries the same task_id attribute."""
        fixed_id = uuid4()
        exporter, tracer = _install_otel_exporter()
        orc = _make_orchestrator(tracer=tracer)

        await orc.run(_base_request(task_id=fixed_id))

        spans = {s.name: s for s in exporter.get_finished_spans()}
        required_spans = {
            "orchestrator.run",
            "pre-pii-scrub",
            "policy-eval",
            "jit-token-issue",
            "llm-invoke",
            "post-sanitize",
        }
        missing = required_spans - spans.keys()
        assert not missing, f"Expected spans not found: {missing}"

        for name in required_spans:
            span = spans[name]
            actual = span.attributes.get("task_id")
            assert actual == str(fixed_id), (
                f"Span '{name}' has task_id={actual!r}; expected {fixed_id!s}"
            )

    @pytest.mark.asyncio
    async def test_task_id_in_every_audit_event(self) -> None:
        """Every AuditLogger event emitted during a run() carries the same task_id."""
        fixed_id = uuid4()
        audit = RecordingAuditLogger()
        orc = _make_orchestrator(audit_logger=audit)

        await orc.run(_base_request(task_id=fixed_id))

        assert audit.events, "No audit events were captured — at least token_issued is expected"
        for evt in audit.events:
            assert "task_id" in evt, (
                f"Audit event '{evt['event']}' is missing task_id field"
            )
            assert evt["task_id"] == str(fixed_id), (
                f"Audit event '{evt['event']}' has task_id={evt['task_id']!r}; "
                f"expected {fixed_id!s}"
            )

    @pytest.mark.asyncio
    async def test_task_id_in_budget_pre_check_audit_event(self) -> None:
        """When a budget session is active, the pre-check audit event carries task_id."""
        from src.watchdog.budget_enforcer import BudgetEnforcer  # local import for clarity

        fixed_task_id = uuid4()
        budget_session_id = uuid4()
        audit = RecordingAuditLogger()
        enforcer = BudgetEnforcer(audit_logger=audit)
        enforcer.create_session(budget_session_id, "general", Decimal("10.0"))

        orc = _make_orchestrator(audit_logger=audit, budget_enforcer=enforcer)

        await orc.run(
            _base_request(
                task_id=fixed_task_id,
                budget_session_id=budget_session_id,
            )
        )

        budget_events = [e for e in audit.events if e["event"] == "budget.pre_check"]
        assert budget_events, "budget.pre_check audit event was not emitted"
        for e in budget_events:
            assert e.get("task_id") == str(fixed_task_id), (
                f"budget.pre_check event has task_id={e.get('task_id')!r}; "
                f"expected {fixed_task_id!s}"
            )


# ---------------------------------------------------------------------------
# 3. Negative — MissingTaskIdError guard
# ---------------------------------------------------------------------------


class TestMissingTaskIdGuard:
    """task_id=None (forced via model_construct) must be caught before Stage 4."""

    def _request_with_null_task_id(self) -> OrchestratorRequest:
        """Create an OrchestratorRequest that bypasses Pydantic validation."""
        return OrchestratorRequest.model_construct(
            task_id=None,
            prompt="Hello",
            agent_type="general",
            requester_id="tester-guard",
            session_token=None,
            model="gpt-4o-mini",
            max_tokens=1024,
            temperature=0.7,
            system_prompt="",
            metadata={},
            budget_session_id=None,
            cost_per_token=Decimal("0.000002"),
        )

    @pytest.mark.asyncio
    async def test_raises_missing_task_id_error(self) -> None:
        """run() must raise MissingTaskIdError when task_id is None."""
        orc = _make_orchestrator()
        with pytest.raises(MissingTaskIdError):
            await orc.run(self._request_with_null_task_id())

    @pytest.mark.asyncio
    async def test_llm_adapter_never_called_for_null_task_id(self) -> None:
        """The LLM adapter's complete() must not be invoked if task_id is None."""
        spy_adapter = MagicMock(spec=_StubAdapter)
        spy_adapter.complete = AsyncMock()

        orc = Orchestrator(
            adapter=spy_adapter,
            guardrails=Guardrails(),
            policy_engine=_mock_policy_engine(),
            session_mgr=SessionManager(),
        )

        with pytest.raises(MissingTaskIdError):
            await orc.run(self._request_with_null_task_id())

        spy_adapter.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_task_id_error_is_value_error_subclass(self) -> None:
        """MissingTaskIdError must be a ValueError so routers map it to HTTP 400."""
        assert issubclass(MissingTaskIdError, ValueError), (
            "MissingTaskIdError must subclass ValueError"
        )

    @pytest.mark.asyncio
    async def test_missing_task_id_error_message_is_descriptive(self) -> None:
        """The error message must convey the requirement for caller diagnostics."""
        orc = _make_orchestrator()
        with pytest.raises(MissingTaskIdError, match="task_id"):
            await orc.run(self._request_with_null_task_id())


# ---------------------------------------------------------------------------
# 4. Concurrency — zero cross-contamination
# ---------------------------------------------------------------------------


class TestConcurrencyNoLeakage:
    """20 concurrent tasks with distinct task_ids produce zero cross-contamination."""

    TASK_COUNT = 20

    @pytest.mark.asyncio
    async def test_20_concurrent_tasks_no_cross_contamination(self) -> None:
        """Every audit event references exactly one of the 20 submitted task_ids."""
        audit = RecordingAuditLogger()
        orc = _make_orchestrator(audit_logger=audit)

        task_ids = [uuid4() for _ in range(self.TASK_COUNT)]
        requests = [
            _base_request(
                task_id=tid,
                prompt=f"Concurrent task prompt {i}",
                requester_id=f"user-{i:03d}",
            )
            for i, tid in enumerate(task_ids)
        ]

        results: list[OrchestratorResult] = await asyncio.gather(
            *[orc.run(r) for r in requests]
        )

        # Every result task_id must be one of the 20 submitted task_ids
        result_task_ids = {r.task_id for r in results}
        assert result_task_ids == set(task_ids), (
            "Result task_ids do not match the submitted set — "
            f"expected {len(task_ids)}, got {len(result_task_ids)}"
        )

        # Every audit event must carry a task_id from the submitted set
        expected_str_ids = {str(tid) for tid in task_ids}
        for evt in audit.events:
            assert "task_id" in evt, (
                f"Audit event '{evt['event']}' is missing task_id"
            )
            assert evt["task_id"] in expected_str_ids, (
                f"Audit event '{evt['event']}' has unexpected task_id={evt['task_id']!r}"
            )

    @pytest.mark.asyncio
    async def test_all_20_task_ids_appear_in_audit_trail(self) -> None:
        """Every submitted task_id leaves at least one audit footprint."""
        audit = RecordingAuditLogger()
        orc = _make_orchestrator(audit_logger=audit)

        task_ids = [uuid4() for _ in range(self.TASK_COUNT)]
        requests = [
            _base_request(task_id=tid, requester_id=f"user-{i:03d}")
            for i, tid in enumerate(task_ids)
        ]

        await asyncio.gather(*[orc.run(r) for r in requests])

        traced_ids = {evt["task_id"] for evt in audit.events if "task_id" in evt}
        missing_from_audit = {str(tid) for tid in task_ids} - traced_ids
        assert not missing_from_audit, (
            f"These task_ids produced no audit events: {missing_from_audit}"
        )

    @pytest.mark.asyncio
    async def test_concurrent_results_maintain_correct_task_id_mapping(self) -> None:
        """result.task_id must equal the task_id supplied in the matching request."""
        orc = _make_orchestrator()
        task_ids = [uuid4() for _ in range(self.TASK_COUNT)]

        results: list[OrchestratorResult] = await asyncio.gather(
            *[orc.run(_base_request(task_id=tid)) for tid in task_ids]
        )

        returned_ids = {r.task_id for r in results}
        input_ids = set(task_ids)
        assert returned_ids == input_ids, (
            "Some results returned a task_id that was not in the input set — "
            "possible cross-contamination between concurrent coroutines"
        )
