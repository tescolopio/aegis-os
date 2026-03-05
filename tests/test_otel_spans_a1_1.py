"""A1-1 — Named OTel spans attached to every orchestrator stage.

Four test classes cover the full A1-1 testing contract:

    TestSpanNames        — exactly five stage spans in documented order
    TestSpanAttributes   — task_id, agent_type, span.status on all spans;
                           error=true + error.message on denied/errored spans
    TestParentHierarchy  — all stage spans share trace_id and are direct
                           children of the ``orchestrator.run`` root span
    TestNoOrphanedSpans  — mid-stage exception leaves no open spans
                           (end_time != None) and sets correct OTel StatusCodes
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from src.adapters.base import BaseAdapter, LLMRequest, LLMResponse
from src.control_plane.orchestrator import Orchestrator, OrchestratorRequest, PolicyDeniedError
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager

# ---------------------------------------------------------------------------
# A1-1 contract constants
# ---------------------------------------------------------------------------

#: The five required stage span names in documented pipeline order.
STAGE_SPAN_NAMES: list[str] = [
    "pre-pii-scrub",
    "policy-eval",
    "jit-token-issue",
    "llm-invoke",
    "post-sanitize",
]

ROOT_SPAN_NAME = "orchestrator.run"
SENTINEL_TOKEN = "test.bearer.token"

_BASE_REQUEST = OrchestratorRequest(
    prompt="Explain the quarterly audit findings in plain language.",
    agent_type="audit",
    requester_id="auditor-001",
    model="gpt-4o-mini",
)


# ---------------------------------------------------------------------------
# Minimal stubs / factories
# ---------------------------------------------------------------------------


class _StubAdapter(BaseAdapter):
    """Minimal async adapter that always returns a canned, PII-free response."""

    @property
    def provider_name(self) -> str:
        """Return a fixed provider label used in LLMResponse."""
        return "stub"

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Return a fixed LLMResponse — no external calls made."""
        return LLMResponse(
            content="Quarterly audit results: no anomalies found.",
            tokens_used=15,
            model=request.model,
            provider="stub",
            finish_reason="stop",
        )


def _make_allow_engine() -> PolicyEngine:
    """Return a PolicyEngine mock that always allows requests."""
    pe: PolicyEngine = MagicMock(spec=PolicyEngine)

    async def _allow(*_a: Any, **_kw: Any) -> PolicyResult:
        return PolicyResult(allowed=True)

    pe.evaluate = _allow  # type: ignore[method-assign]
    return pe


def _make_deny_engine() -> PolicyEngine:
    """Return a PolicyEngine mock that always denies requests.

    The orchestrator maps ``allowed=False`` to ``PolicyDeniedError``, which
    allows us to verify error attributes on the ``policy-eval`` span.
    """
    pe: PolicyEngine = MagicMock(spec=PolicyEngine)

    async def _deny(*_a: Any, **_kw: Any) -> PolicyResult:
        return PolicyResult(allowed=False, reasons=["test-deny-reason"])

    pe.evaluate = _deny  # type: ignore[method-assign]
    return pe


def _make_session_mgr(
    *,
    raise_on_issue: Exception | None = None,
) -> SessionManager:
    """Return a SessionManager mock.

    When *raise_on_issue* is provided, ``issue_token`` raises that exception
    (used to trigger a mid-stage failure inside the ``jit-token-issue`` span).
    """
    sm: SessionManager = MagicMock(spec=SessionManager)
    if raise_on_issue is not None:
        sm.issue_token.side_effect = raise_on_issue  # type: ignore[union-attr]
    else:
        sm.issue_token.return_value = SENTINEL_TOKEN  # type: ignore[union-attr]
        sm.validate_token.return_value = MagicMock(  # type: ignore[union-attr]
            jti="test-jti",
            agent_type=_BASE_REQUEST.agent_type,
        )
    return sm


# ---------------------------------------------------------------------------
# Shared OTel per-test fixture mixin
# ---------------------------------------------------------------------------


class _OtelFixture:
    """Mixin that provisions an isolated TracerProvider + InMemorySpanExporter
    for each test method.

    Rather than fighting the OTel global-provider singleton, each test
    constructs its own ``TracerProvider`` and injects the resulting tracer
    directly into the ``Orchestrator`` via the ``tracer=`` constructor
    parameter.  This guarantees complete span isolation between tests.
    """

    exporter: InMemorySpanExporter
    controlled_tracer: Any  # opentelemetry.trace.Tracer

    @pytest.fixture(autouse=True)
    def _install_otel(self) -> Any:
        """Install an in-memory span exporter scoped to this test only."""
        self.exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.controlled_tracer = provider.get_tracer(
            "test.otel.a1_1",
            schema_url="https://opentelemetry.io/schemas/1.11.0",
        )
        yield
        self.exporter.clear()

    def _all_spans(self) -> list[Any]:
        """Return all finished spans collected by this test's exporter."""
        return list(self.exporter.get_finished_spans())

    def _stage_spans(self) -> list[Any]:
        """Return only the five required stage spans, in export order."""
        return [s for s in self._all_spans() if s.name in STAGE_SPAN_NAMES]

    def _orchestrator(
        self,
        *,
        policy_engine: PolicyEngine | None = None,
        session_mgr: SessionManager | None = None,
    ) -> Orchestrator:
        """Build an Orchestrator with stubs, injecting this test's tracer."""
        return Orchestrator(
            adapter=_StubAdapter(),
            policy_engine=policy_engine if policy_engine is not None else _make_allow_engine(),
            session_mgr=session_mgr if session_mgr is not None else _make_session_mgr(),
            tracer=self.controlled_tracer,
        )


# ---------------------------------------------------------------------------
# 1. Span names — exactly five stage spans in documented order
# ---------------------------------------------------------------------------


class TestSpanNames(_OtelFixture):
    """Assert exactly the five required stage spans are exported in documented order."""

    @pytest.mark.asyncio
    async def test_exactly_five_stage_spans(self) -> None:
        """Run one task; assert stage span count is exactly five."""
        await self._orchestrator().run(_BASE_REQUEST)

        stage_spans = self._stage_spans()
        assert len(stage_spans) == 5, (
            f"Expected exactly 5 stage spans; got {len(stage_spans)}.\n"
            f"  all span names: {[s.name for s in self._all_spans()]}"
        )

    @pytest.mark.asyncio
    async def test_stage_span_names_match_exactly(self) -> None:
        """Stage span names must match the A1-1 contract names character-for-character."""
        await self._orchestrator().run(_BASE_REQUEST)

        names = [s.name for s in self._stage_spans()]
        assert names == STAGE_SPAN_NAMES, (
            f"Stage span names do not match A1-1 contract.\n"
            f"  expected: {STAGE_SPAN_NAMES}\n"
            f"  got:      {names}"
        )

    @pytest.mark.asyncio
    async def test_root_span_orchestrator_run_is_exported(self) -> None:
        """The enclosing orchestrator.run root span must be exported."""
        await self._orchestrator().run(_BASE_REQUEST)

        root_spans = [s for s in self._all_spans() if s.name == ROOT_SPAN_NAME]
        assert len(root_spans) == 1, (
            f"Expected exactly one '{ROOT_SPAN_NAME}' span; got {len(root_spans)}.\n"
            f"  all span names: {[s.name for s in self._all_spans()]}"
        )


# ---------------------------------------------------------------------------
# 2. Span attributes — task_id, agent_type, span.status; error attributes
# ---------------------------------------------------------------------------


class TestSpanAttributes(_OtelFixture):
    """Assert mandatory attributes are present on all spans and error attributes
    appear on denied / errored spans."""

    @pytest.mark.asyncio
    async def test_happy_path_all_stage_spans_carry_required_attributes(self) -> None:
        """Every stage span must carry task_id, agent_type, and span.status='OK'."""
        result = await self._orchestrator().run(_BASE_REQUEST)
        task_id_str = str(result.task_id)

        for span in self._stage_spans():
            attrs: dict[str, Any] = dict(span.attributes or {})
            assert attrs.get("task_id") == task_id_str, (
                f"Span '{span.name}' missing or wrong task_id.\n  attributes: {attrs}"
            )
            assert attrs.get("agent_type") == _BASE_REQUEST.agent_type, (
                f"Span '{span.name}' missing or wrong agent_type.\n  attributes: {attrs}"
            )
            assert "span.status" in attrs, (
                f"Span '{span.name}' missing mandatory 'span.status' attribute."
                f"\n  attributes: {attrs}"
            )
            assert attrs["span.status"] == "OK", (
                f"Span '{span.name}' expected span.status='OK'; "
                f"got {attrs['span.status']!r}.\n  attributes: {attrs}"
            )

    @pytest.mark.asyncio
    async def test_policy_denied_span_carries_error_attributes(self) -> None:
        """policy-eval span for a denied request must carry error=True and error.message."""
        orc = self._orchestrator(policy_engine=_make_deny_engine())
        with pytest.raises(PolicyDeniedError):
            await orc.run(_BASE_REQUEST)

        policy_spans = [s for s in self._all_spans() if s.name == "policy-eval"]
        assert len(policy_spans) == 1, (
            f"Expected exactly one 'policy-eval' span; got {len(policy_spans)}"
        )
        attrs: dict[str, Any] = dict(policy_spans[0].attributes or {})

        assert attrs.get("span.status") == "ERROR", (
            f"Denied policy-eval span must have span.status='ERROR'; "
            f"got {attrs.get('span.status')!r}"
        )
        assert attrs.get("error") is True, (
            "Denied policy-eval span must carry error=True"
        )
        assert attrs.get("error.message"), (
            "Denied policy-eval span must carry a non-empty error.message"
        )

    @pytest.mark.asyncio
    async def test_session_mgr_failure_span_carries_error_attributes(self) -> None:
        """jit-token-issue span for a SessionManager failure carries error attributes."""
        orc = self._orchestrator(
            session_mgr=_make_session_mgr(
                raise_on_issue=RuntimeError("token backend unavailable")
            )
        )
        with pytest.raises(RuntimeError, match="token backend unavailable"):
            await orc.run(_BASE_REQUEST)

        token_spans = [s for s in self._all_spans() if s.name == "jit-token-issue"]
        assert len(token_spans) == 1, (
            f"Expected exactly one 'jit-token-issue' span; got {len(token_spans)}"
        )
        attrs = dict(token_spans[0].attributes or {})

        assert attrs.get("span.status") == "ERROR"
        assert attrs.get("error") is True
        assert "error.message" in attrs
        assert "token backend unavailable" in str(attrs["error.message"])


# ---------------------------------------------------------------------------
# 3. Parent-child hierarchy — single trace_id; all stage spans are children
#    of the orchestrator.run root span
# ---------------------------------------------------------------------------


class TestParentHierarchy(_OtelFixture):
    """All five stage spans must share a single trace_id and be direct
    children of the ``orchestrator.run`` root span."""

    @pytest.mark.asyncio
    async def test_all_stage_spans_share_trace_id_with_root(self) -> None:
        """Every stage span's trace_id must equal the root span's trace_id."""
        await self._orchestrator().run(_BASE_REQUEST)

        all_spans = self._all_spans()
        root_spans = [s for s in all_spans if s.name == ROOT_SPAN_NAME]
        assert len(root_spans) == 1, (
            f"Expected exactly one root span; got {[s.name for s in all_spans]}"
        )
        root = root_spans[0]
        stage_spans = self._stage_spans()
        assert len(stage_spans) == 5

        for span in stage_spans:
            assert span.context.trace_id == root.context.trace_id, (
                f"Span '{span.name}' has trace_id "
                f"{span.context.trace_id!r} — expected {root.context.trace_id!r} "
                f"(same as '{ROOT_SPAN_NAME}')"
            )

    @pytest.mark.asyncio
    async def test_all_stage_spans_are_direct_children_of_root(self) -> None:
        """Every stage span's parent span_id must equal the root span's span_id."""
        await self._orchestrator().run(_BASE_REQUEST)

        all_spans = self._all_spans()
        root = next(s for s in all_spans if s.name == ROOT_SPAN_NAME)

        for span in self._stage_spans():
            assert span.parent is not None, (
                f"Span '{span.name}' has no parent — expected it to be a child "
                f"of '{ROOT_SPAN_NAME}'"
            )
            assert span.parent.span_id == root.context.span_id, (
                f"Span '{span.name}' parent span_id {span.parent.span_id!r} "
                f"!= root span_id {root.context.span_id!r}"
            )


# ---------------------------------------------------------------------------
# 4. No orphaned spans (negative test) — mid-stage exception
# ---------------------------------------------------------------------------


class TestNoOrphanedSpans(_OtelFixture):
    """Inject a mid-stage exception and verify every opened span is fully closed.

    The exception is injected at Stage 3 (jit-token-issue) by making
    ``SessionManager.issue_token`` raise a ``RuntimeError``.  At that point:

    * ``pre-pii-scrub`` — already closed (OK)
    * ``policy-eval``   — already closed (OK)
    * ``jit-token-issue`` — closed with ERROR status
    * ``llm-invoke`` / ``post-sanitize`` — never opened
    * ``orchestrator.run`` — closed with ERROR status (outermost span)
    """

    @pytest.mark.asyncio
    async def test_no_span_has_none_end_time_after_exception(self) -> None:
        """Use the in-memory exporter to assert no span has end_time == None."""
        orc = self._orchestrator(
            session_mgr=_make_session_mgr(
                raise_on_issue=RuntimeError("injected mid-stage failure")
            )
        )
        with pytest.raises(RuntimeError, match="injected mid-stage failure"):
            await orc.run(_BASE_REQUEST)

        finished = self._all_spans()
        assert finished, (
            "At least some spans must have been exported after the exception"
        )
        for span in finished:
            assert span.end_time is not None, (
                f"Span '{span.name}' has end_time=None — it was left open "
                "after the mid-stage exception was handled"
            )

    @pytest.mark.asyncio
    async def test_pre_exception_spans_have_correct_status_codes(self) -> None:
        """Pre-exception stage spans are OK; the failing stage span is ERROR.

        Spans that ran successfully before the exception must carry
        ``StatusCode.OK``.  The stage that raised must carry
        ``StatusCode.ERROR``.  Stages that were never reached must not appear.
        """
        orc = self._orchestrator(
            session_mgr=_make_session_mgr(
                raise_on_issue=RuntimeError("injected for status-code check")
            )
        )
        with pytest.raises(RuntimeError):
            await orc.run(_BASE_REQUEST)

        finished_by_name: dict[str, Any] = {s.name: s for s in self._all_spans()}

        # Stages that completed before the exception must be OK.
        for name in ("pre-pii-scrub", "policy-eval"):
            assert name in finished_by_name, (
                f"Expected span '{name}' to be exported (it ran before the failure)"
            )
            span = finished_by_name[name]
            assert span.status.status_code == StatusCode.OK, (
                f"Span '{name}' expected StatusCode.OK; "
                f"got {span.status.status_code!r}"
            )

        # The failing stage must be ERROR.
        assert "jit-token-issue" in finished_by_name, (
            "Expected 'jit-token-issue' span to be exported (it is where the failure occurred)"
        )
        failing = finished_by_name["jit-token-issue"]
        assert failing.status.status_code == StatusCode.ERROR, (
            f"Span 'jit-token-issue' expected StatusCode.ERROR; "
            f"got {failing.status.status_code!r}"
        )

        # Stages that were never reached must not have been exported.
        for name in ("llm-invoke", "post-sanitize"):
            assert name not in finished_by_name, (
                f"Span '{name}' should NOT be in the exporter — "
                "its stage was never reached due to the mid-pipeline exception"
            )
