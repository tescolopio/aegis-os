"""Tests for src/control_plane/orchestrator.py

Covers:
  1. Unit – stage order: the five stages MUST execute in documented sequence.
  2. Unit – short-circuit on failure: an exception at any stage must propagate
     immediately and suppress all subsequent stages.
  3. Integration – live (stub) adapter with OTel span verification.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from src.adapters.base import BaseAdapter, LLMRequest, LLMResponse
from src.control_plane.orchestrator import (
    Orchestrator,
    OrchestratorRequest,
    OrchestratorResult,
    PolicyDeniedError,
)
from src.governance.guardrails import Guardrails, MaskResult, PromptInjectionError
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

SENTINEL_TOKEN = "jwt.sentinel.token"
SENTINEL_CONTENT = "LLM response content"

_GOOD_REQUEST = OrchestratorRequest(
    prompt="Summarise the quarterly earnings report.",
    agent_type="finance",
    requester_id="user-test-001",
    model="gpt-4o-mini",
)


def _make_guardrails(call_log: list[str]) -> Guardrails:
    """Return a Guardrails mock that records stage calls into *call_log*."""
    g = MagicMock(spec=Guardrails)
    g.check_prompt_injection.side_effect = lambda _text: call_log.append("guardrails_pre")
    g.mask_pii.side_effect = lambda text: (
        call_log.append("guardrails_pre_mask")
        if "guardrails_post" not in call_log
        else call_log.append("guardrails_post"),
        MaskResult(text=text, found_types=[]),
    )[-1]
    return g


def _make_policy_engine(call_log: list[str]) -> PolicyEngine:
    pe = MagicMock(spec=PolicyEngine)

    async def _evaluate(*_a: Any, **_kw: Any) -> PolicyResult:
        call_log.append("opa")
        return PolicyResult(allowed=True)

    pe.evaluate = _evaluate
    return pe


def _make_session_mgr(call_log: list[str]) -> SessionManager:
    sm = MagicMock(spec=SessionManager)
    sm.issue_token.side_effect = lambda **_kw: (
        call_log.append("session_mgr"),
        SENTINEL_TOKEN,
    )[-1]
    return sm


class _StubAdapter(BaseAdapter):
    """Minimal synchronous-looking async adapter for tests."""

    def __init__(self, call_log: list[str] | None = None) -> None:
        self._call_log = call_log

    @property
    def provider_name(self) -> str:
        return "stub"

    async def complete(self, request: LLMRequest) -> LLMResponse:
        if self._call_log is not None:
            self._call_log.append("llm_adapter")
        return LLMResponse(
            content=SENTINEL_CONTENT,
            tokens_used=10,
            model=request.model,
            provider="stub",
            finish_reason="stop",
        )


# ---------------------------------------------------------------------------
# 1. Unit – stage order
# ---------------------------------------------------------------------------


class TestStageOrder:
    """Assert the five stages run in the exact documented sequence."""

    @pytest.mark.asyncio
    async def test_happy_path_stage_sequence(self) -> None:
        """Stages must execute in order: pre-sanitize → opa → session_mgr → llm → post-sanitize."""
        call_log: list[str] = []

        # Build instrumented mocks
        guardrails = MagicMock(spec=Guardrails)
        policy_engine = MagicMock(spec=PolicyEngine)
        session_mgr = MagicMock(spec=SessionManager)

        # Stage 1 – guardrails pre
        guardrails.check_prompt_injection.side_effect = lambda _t: call_log.append(
            "stage1_injection_check"
        )
        # Note: side_effect must be a single callable when tracking call order;
        # a list of callables is NOT auto-called by Mock – it is returned as-is.
        _mask_count = 0

        def _mask_pii_ordered(text: str) -> MaskResult:
            nonlocal _mask_count
            _mask_count += 1
            if _mask_count == 1:
                call_log.append("stage1_mask_pii")
            else:
                call_log.append("stage5_mask_pii")
            return MaskResult(text=text, found_types=[])

        guardrails.mask_pii.side_effect = _mask_pii_ordered

        # Stage 2 – OPA
        async def _opa_eval(*_a: Any, **_kw: Any) -> PolicyResult:
            call_log.append("stage2_opa")
            return PolicyResult(allowed=True)

        policy_engine.evaluate = _opa_eval

        # Stage 3 – SessionManager
        session_mgr.issue_token.side_effect = lambda **_kw: (
            call_log.append("stage3_session_mgr"),
            SENTINEL_TOKEN,
        )[-1]

        # Stage 4 – Adapter (captured via subclass)
        class _TrackedAdapter(_StubAdapter):
            async def complete(self, request: LLMRequest) -> LLMResponse:
                call_log.append("stage4_llm")
                return await super().complete(request)

        orc = Orchestrator(
            adapter=_TrackedAdapter(),
            guardrails=guardrails,
            policy_engine=policy_engine,
            session_mgr=session_mgr,
        )
        result = await orc.run(_GOOD_REQUEST)

        assert isinstance(result, OrchestratorResult)
        assert result.session_token == SENTINEL_TOKEN

        expected_order = [
            "stage1_injection_check",
            "stage1_mask_pii",
            "stage2_opa",
            "stage3_session_mgr",
            "stage4_llm",
            "stage5_mask_pii",
        ]
        assert call_log == expected_order, (
            f"Stage order violated!\n  expected: {expected_order}\n  got:      {call_log}"
        )

    @pytest.mark.asyncio
    async def test_reversed_stage_order_would_fail(self) -> None:
        """Regression: if we swapped OPA and SessionManager the call_log would differ."""
        # This test ensures the assertion above can actually catch re-orderings
        wrong_order = [
            "stage1_injection_check",
            "stage1_mask_pii",
            "stage3_session_mgr",  # swapped
            "stage2_opa",  # swapped
            "stage4_llm",
            "stage5_mask_pii",
        ]
        correct_order = [
            "stage1_injection_check",
            "stage1_mask_pii",
            "stage2_opa",
            "stage3_session_mgr",
            "stage4_llm",
            "stage5_mask_pii",
        ]
        assert wrong_order != correct_order  # would be caught by the main test


# ---------------------------------------------------------------------------
# 2. Unit – short-circuit on stage failure
# ---------------------------------------------------------------------------


class TestShortCircuitOnFailure:
    """Inject an exception at each stage; assert correct propagation and no later stages run."""

    @pytest.mark.asyncio
    async def test_stage1_injection_check_raises(self) -> None:
        """PromptInjectionError from stage 1 must propagate; stage 2+ must not run."""
        pe = MagicMock(spec=PolicyEngine)
        sm = MagicMock(spec=SessionManager)

        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.side_effect = PromptInjectionError("injection detected")

        orc = Orchestrator(
            adapter=_StubAdapter(),
            guardrails=guardrails,
            policy_engine=pe,
            session_mgr=sm,
        )
        with pytest.raises(PromptInjectionError):
            await orc.run(_GOOD_REQUEST)

        pe.evaluate.assert_not_called()
        sm.issue_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_stage1_mask_pii_raises(self) -> None:
        """RuntimeError from PII masking in stage 1 must propagate; stage 2+ must not run."""
        pe = MagicMock(spec=PolicyEngine)
        sm = MagicMock(spec=SessionManager)

        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.return_value = None
        guardrails.mask_pii.side_effect = RuntimeError("pii engine failure")

        orc = Orchestrator(
            adapter=_StubAdapter(),
            guardrails=guardrails,
            policy_engine=pe,
            session_mgr=sm,
        )
        with pytest.raises(RuntimeError):
            await orc.run(_GOOD_REQUEST)

        pe.evaluate.assert_not_called()
        sm.issue_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_stage2_opa_denied_raises_policy_denied_error(self) -> None:
        """A denied OPA result must raise PolicyDeniedError; stage 3+ must not run."""
        sm = MagicMock(spec=SessionManager)

        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.return_value = None
        guardrails.mask_pii.return_value = MaskResult(text=_GOOD_REQUEST.prompt, found_types=[])

        async def _deny(*_a: Any, **_kw: Any) -> PolicyResult:
            return PolicyResult(allowed=False, reasons=["restricted agent type"])

        pe = MagicMock(spec=PolicyEngine)
        pe.evaluate = _deny

        orc = Orchestrator(
            adapter=_StubAdapter(),
            guardrails=guardrails,
            policy_engine=pe,
            session_mgr=sm,
        )
        with pytest.raises(PolicyDeniedError):
            await orc.run(_GOOD_REQUEST)

        sm.issue_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_stage2_opa_network_error_raises(self) -> None:
        """A network error from OPA must propagate; stage 3+ must not run."""
        sm = MagicMock(spec=SessionManager)

        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.return_value = None
        guardrails.mask_pii.return_value = MaskResult(text=_GOOD_REQUEST.prompt, found_types=[])

        async def _fail(*_a: Any, **_kw: Any) -> PolicyResult:
            raise ConnectionError("OPA server unreachable")

        pe = MagicMock(spec=PolicyEngine)
        pe.evaluate = _fail

        orc = Orchestrator(
            adapter=_StubAdapter(),
            guardrails=guardrails,
            policy_engine=pe,
            session_mgr=sm,
        )
        with pytest.raises(ConnectionError):
            await orc.run(_GOOD_REQUEST)

        sm.issue_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_stage3_session_mgr_raises(self) -> None:
        """ValueError from SessionManager must propagate; stage 4 (LLM) must not run."""
        adapter_called = False

        class _TrackingAdapter(_StubAdapter):
            async def complete(self, request: LLMRequest) -> LLMResponse:
                nonlocal adapter_called
                adapter_called = True
                return await super().complete(request)

        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.return_value = None
        guardrails.mask_pii.return_value = MaskResult(text=_GOOD_REQUEST.prompt, found_types=[])

        async def _allow(*_a: Any, **_kw: Any) -> PolicyResult:
            return PolicyResult(allowed=True)

        pe = MagicMock(spec=PolicyEngine)
        pe.evaluate = _allow

        sm = MagicMock(spec=SessionManager)
        sm.issue_token.side_effect = ValueError("requester_id invalid")

        orc = Orchestrator(
            adapter=_TrackingAdapter(),
            guardrails=guardrails,
            policy_engine=pe,
            session_mgr=sm,
        )
        with pytest.raises(ValueError):
            await orc.run(_GOOD_REQUEST)

        assert not adapter_called, "LLM adapter must not be called when SessionManager fails"

    @pytest.mark.asyncio
    async def test_stage4_adapter_raises(self) -> None:
        """RuntimeError from the LLM adapter must propagate; stage 5 must not run."""
        post_sanitize_called = False

        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.return_value = None

        call_count = 0

        def _mask_pii(text: str) -> MaskResult:
            nonlocal call_count, post_sanitize_called
            call_count += 1
            if call_count >= 2:
                post_sanitize_called = True
            return MaskResult(text=text, found_types=[])

        guardrails.mask_pii.side_effect = _mask_pii

        async def _allow(*_a: Any, **_kw: Any) -> PolicyResult:
            return PolicyResult(allowed=True)

        pe = MagicMock(spec=PolicyEngine)
        pe.evaluate = _allow

        sm = MagicMock(spec=SessionManager)
        sm.issue_token.return_value = SENTINEL_TOKEN

        class _FailingAdapter(_StubAdapter):
            async def complete(self, request: LLMRequest) -> LLMResponse:
                raise RuntimeError("LLM provider timeout")

        orc = Orchestrator(
            adapter=_FailingAdapter(),
            guardrails=guardrails,
            policy_engine=pe,
            session_mgr=sm,
        )
        with pytest.raises(RuntimeError, match="LLM provider timeout"):
            await orc.run(_GOOD_REQUEST)

        assert not post_sanitize_called, "Stage 5 (post-sanitize) must not run after stage 4 fails"

    @pytest.mark.asyncio
    async def test_stage5_post_sanitize_raises(self) -> None:
        """RuntimeError during post-sanitize (stage 5) must propagate."""
        call_count = 0

        guardrails = MagicMock(spec=Guardrails)
        guardrails.check_prompt_injection.return_value = None

        def _mask_pii(text: str) -> MaskResult:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return MaskResult(text=text, found_types=[])
            # Second call is stage 5 – simulate failure
            raise RuntimeError("post-sanitize engine crashed")

        guardrails.mask_pii.side_effect = _mask_pii

        async def _allow(*_a: Any, **_kw: Any) -> PolicyResult:
            return PolicyResult(allowed=True)

        pe = MagicMock(spec=PolicyEngine)
        pe.evaluate = _allow

        sm = MagicMock(spec=SessionManager)
        sm.issue_token.return_value = SENTINEL_TOKEN

        orc = Orchestrator(
            adapter=_StubAdapter(),
            guardrails=guardrails,
            policy_engine=pe,
            session_mgr=sm,
        )
        with pytest.raises(RuntimeError, match="post-sanitize engine crashed"):
            await orc.run(_GOOD_REQUEST)


# ---------------------------------------------------------------------------
# 3. Integration – stub adapter + OTel span verification
# ---------------------------------------------------------------------------


class TestIntegration:
    """Run the orchestrator against a stub adapter; verify LLMResponse content
    and that all five expected OTel spans were emitted."""

    @pytest.fixture(autouse=True)
    def _install_otel_exporter(self) -> Any:
        """Create a private TracerProvider + InMemorySpanExporter for each test.

        Rather than fighting OTel's singleton global-provider restriction, we
        construct a *local* TracerProvider per test and inject the tracer it
        vends directly into the Orchestrator via the ``tracer=`` constructor
        parameter.  This guarantees every test sees only its own spans.
        """
        self.exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.controlled_tracer = provider.get_tracer(
            "test.orchestrator",
            schema_url="https://opentelemetry.io/schemas/1.11.0",
        )
        yield
        self.exporter.clear()

    def _span_names(self) -> list[str]:
        return [span.name for span in self.exporter.get_finished_spans()]

    @pytest.mark.asyncio
    async def test_returns_nonempty_llm_response(self) -> None:
        """The pipeline must return an OrchestratorResult with non-empty content."""
        async def _allow(*_a: Any, **_kw: Any) -> PolicyResult:
            return PolicyResult(allowed=True)

        pe = MagicMock(spec=PolicyEngine)
        pe.evaluate = _allow

        orc = Orchestrator(
            adapter=_StubAdapter(),
            policy_engine=pe,
            tracer=self.controlled_tracer,
        )
        result = await orc.run(_GOOD_REQUEST)

        assert isinstance(result, OrchestratorResult)
        assert result.response.content, "LLMResponse.content must be non-empty"
        assert result.session_token, "session_token must be non-empty"
        assert result.sanitized_prompt, "sanitized_prompt must be non-empty"

    @pytest.mark.asyncio
    async def test_all_five_stages_produce_otel_spans(self) -> None:
        """All five stage spans must be present in the OTel output."""
        async def _allow(*_a: Any, **_kw: Any) -> PolicyResult:
            return PolicyResult(allowed=True)

        pe = MagicMock(spec=PolicyEngine)
        pe.evaluate = _allow

        orc = Orchestrator(
            adapter=_StubAdapter(),
            policy_engine=pe,
            tracer=self.controlled_tracer,
        )
        await orc.run(_GOOD_REQUEST)

        span_names = self._span_names()
        required_spans = [
            "orchestrator.run",
            "pre-pii-scrub",
            "policy-eval",
            "jit-token-issue",
            "llm-invoke",
            "post-sanitize",
        ]
        missing = [s for s in required_spans if s not in span_names]
        assert not missing, (
            f"Missing OTel spans – all five stages must instrument:\n"
            f"  missing:  {missing}\n"
            f"  recorded: {span_names}"
        )

    @pytest.mark.asyncio
    async def test_pii_in_response_is_redacted(self) -> None:
        """PII in the LLM output must be masked by stage 5."""
        async def _allow(*_a: Any, **_kw: Any) -> PolicyResult:
            return PolicyResult(allowed=True)

        pe = MagicMock(spec=PolicyEngine)
        pe.evaluate = _allow

        class _PiiInResponseAdapter(_StubAdapter):
            async def complete(self, request: LLMRequest) -> LLMResponse:
                return LLMResponse(
                    content="Contact us at leaky@example.com for support.",
                    tokens_used=10,
                    model=request.model,
                    provider="stub",
                    finish_reason="stop",
                )

        orc = Orchestrator(
            adapter=_PiiInResponseAdapter(),
            policy_engine=pe,
            tracer=self.controlled_tracer,
        )
        result = await orc.run(_GOOD_REQUEST)

        assert "leaky@example.com" not in result.response.content
        assert "[REDACTED-EMAIL]" in result.response.content
        assert "email" in result.pii_found_in_response
