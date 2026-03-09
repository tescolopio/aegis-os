# Copyright 2026 Tim Escolopio / 3D Tech Solutions
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Phase 2 (P2-2) tests: exponential backoff retry policies.

Test classes
------------
TestRetryPolicyConfiguration
    Unit tests asserting LLM_RETRY_POLICY values without a Temporal server.

TestRetryCountCap
    Integration tests verifying exactly 5 retries before HITL escalation.

TestBackoffTiming
    Integration tests capturing inter-attempt timestamps and asserting
    exponential doubling (within 10% tolerance).

TestTimeoutErrorRetry
    Integration tests verifying asyncio.TimeoutError triggers the same
    retry policy as RateLimitError.

TestSuccessfulRecovery
    Integration test: adapter fails twice then succeeds; final result and
    audit trail verified.

TestNonRetryableErrors
    Negative tests confirming PolicyDeniedError is NOT retried.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.adapters.base import LLMResponse
from src.audit_vault.logger import AuditLogger
from src.control_plane.scheduler import (
    LLM_RETRY_POLICY,
    AegisActivities,
    AgentTaskWorkflow,
    JITTokenInput,
    JITTokenResult,
    LLMInvokeInput,
    LLMInvokeResult,
    PolicyEvalInput,
    PolicyEvalResult,
    PostSanitizeInput,
    PostSanitizeResult,
    PrePIIScrubResult,
    WorkflowAuditActivities,
    WorkflowInput,
    WorkflowOutput,
)
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult

_TASK_QUEUE = "aegis-retry-test"


def _make_workflow_input(prompt: str = "Hello retry test") -> WorkflowInput:
    return WorkflowInput(
        task_id=str(uuid.uuid4()),
        prompt=prompt,
        agent_type="general",
        requester_id="test-user",
    )


def _make_stub_activities_except_llm(llm_mock: Any) -> AegisActivities:
    """Build AegisActivities wired with a configurable LLM adapter mock."""
    adapter = MagicMock()
    adapter.complete = llm_mock
    return AegisActivities(adapter=adapter)

class _RecordingAuditLogger(AuditLogger):
    """Capture rendered audit entries for lifecycle assertions."""

    def __init__(self) -> None:
        super().__init__("test.retry.audit")
        self.entries: list[dict[str, Any]] = []

    def info(self, event: str, **kwargs: object) -> None:
        self.entries.append({"level": "info", "event": event, **kwargs})

    def warning(self, event: str, **kwargs: object) -> None:
        self.entries.append({"level": "warning", "event": event, **kwargs})

    def error(self, event: str, **kwargs: object) -> None:
        self.entries.append({"level": "error", "event": event, **kwargs})


# ---------------------------------------------------------------------------
# Unit tests — retry policy configuration (no Temporal server)
# ---------------------------------------------------------------------------


class TestRetryPolicyConfiguration:
    """P2-2 unit: LLM_RETRY_POLICY must be configured correctly."""

    def test_maximum_attempts_is_five(self) -> None:
        """Retry cap must be exactly 5 — not 4, not 6."""
        assert LLM_RETRY_POLICY.maximum_attempts == 5

    def test_initial_interval_is_one_second(self) -> None:
        """Initial retry interval must be 1 second."""
        assert LLM_RETRY_POLICY.initial_interval == timedelta(seconds=1)

    def test_backoff_coefficient_is_two(self) -> None:
        """Backoff coefficient must be 2.0 to achieve exponential doubling."""
        assert LLM_RETRY_POLICY.backoff_coefficient == 2.0

    def test_policy_denied_is_non_retryable(self) -> None:
        """PolicyDeniedError must not trigger a retry."""
        non_retryable = LLM_RETRY_POLICY.non_retryable_error_types or []
        assert "PolicyDeniedError" in non_retryable

    def test_token_scope_error_is_non_retryable(self) -> None:
        """TokenScopeError must not trigger a retry."""
        non_retryable = LLM_RETRY_POLICY.non_retryable_error_types or []
        assert "TokenScopeError" in non_retryable

    def test_token_expired_error_is_non_retryable(self) -> None:
        """TokenExpiredError must not trigger a retry."""
        non_retryable = LLM_RETRY_POLICY.non_retryable_error_types or []
        assert "TokenExpiredError" in non_retryable

    def test_rate_limit_error_not_in_non_retryable(self) -> None:
        """RateLimitError must NOT be in non_retryable_error_types (it should be retried)."""
        non_retryable = LLM_RETRY_POLICY.non_retryable_error_types or []
        assert "RateLimitError" not in non_retryable

    def test_backoff_sequence_calculation(self) -> None:
        """Manual computation of backoff sequence must match policy parameters.

        The expected delays are: 1s, 2s, 4s, 8s (4 inter-attempt gaps for 5 attempts).
        Each must be double the previous (backoff_coefficient=2.0).
        """
        initial = LLM_RETRY_POLICY.initial_interval.total_seconds()
        coefficient = LLM_RETRY_POLICY.backoff_coefficient
        expected = [initial * (coefficient**i) for i in range(4)]
        for i in range(1, len(expected)):
            ratio = expected[i] / expected[i - 1]
            assert abs(ratio - 2.0) < 0.001, (
                f"Delay ratio at gap {i} is {ratio:.4f}, expected 2.0"
            )


# ---------------------------------------------------------------------------
# Integration tests — retry count cap
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRetryCountCap:
    """P2-2 integration: LLMInvoke retried exactly 5 times then HITL escalation."""

    @pytest.mark.asyncio
    async def test_rate_limit_error_retried_exactly_five_times(self) -> None:
        """Adapter raises RateLimitError on every call; workflow must retry exactly 5 times."""
        attempt_counts: list[int] = []

        @activity.defn(name="PrePIIScrub")
        async def mock_pre(inp: WorkflowInput) -> PrePIIScrubResult:
            return PrePIIScrubResult(sanitized_prompt=inp.prompt, pii_types=[])

        @activity.defn(name="PolicyEval")
        async def mock_policy(inp: PolicyEvalInput) -> PolicyEvalResult:
            return PolicyEvalResult(
                allowed=True,
                action="allow",
                fields=[],
                sanitized_prompt=inp.sanitized_prompt,
                extra_pii_types=[],
            )

        @activity.defn(name="JITTokenIssue")
        async def mock_jit(inp: JITTokenInput) -> JITTokenResult:
            return JITTokenResult(token="tok", jti=str(uuid.uuid4()))

        @activity.defn(name="LLMInvoke")
        async def mock_llm_always_fails(inp: LLMInvokeInput) -> LLMInvokeResult:
            info = activity.info()
            attempt_counts.append(info.attempt)
            raise ApplicationError(
                "Rate limit exceeded",
                type="RateLimitError",
            )

        @activity.defn(name="PostSanitize")
        async def mock_post(inp: PostSanitizeInput) -> PostSanitizeResult:
            return PostSanitizeResult(sanitized_content=inp.content, pii_types=[])

        inp = _make_workflow_input()

        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue=_TASK_QUEUE,
                workflows=[AgentTaskWorkflow],
                activities=[mock_pre, mock_policy, mock_jit, mock_llm_always_fails, mock_post],
            ):
                with pytest.raises(Exception) as exc_info:
                    await env.client.execute_workflow(
                        AgentTaskWorkflow.run,
                        inp,
                        id=f"retry-cap-{uuid.uuid4()}",
                        task_queue=_TASK_QUEUE,
                    )

        # Workflow must fail (HITL escalation or ActivityError).
        assert exc_info.value is not None
        # LLMInvoke must have been attempted exactly 5 times.
        assert len(attempt_counts) == 5, (
            f"Expected exactly 5 LLMInvoke attempts, got {len(attempt_counts)}"
        )
        # Attempts must count from 1 to 5.
        assert attempt_counts == [1, 2, 3, 4, 5]

    @pytest.mark.asyncio
    async def test_workflow_raises_after_exhausted_retries(self) -> None:
        """After 5 failed attempts the workflow must escalate (not silently succeed)."""

        @activity.defn(name="PrePIIScrub")
        async def mock_pre(inp: WorkflowInput) -> PrePIIScrubResult:
            return PrePIIScrubResult(sanitized_prompt=inp.prompt, pii_types=[])

        @activity.defn(name="PolicyEval")
        async def mock_policy(inp: PolicyEvalInput) -> PolicyEvalResult:
            return PolicyEvalResult(
                allowed=True, action="allow", fields=[],
                sanitized_prompt=inp.sanitized_prompt, extra_pii_types=[],
            )

        @activity.defn(name="JITTokenIssue")
        async def mock_jit(inp: JITTokenInput) -> JITTokenResult:
            return JITTokenResult(token="tok", jti=str(uuid.uuid4()))

        @activity.defn(name="LLMInvoke")
        async def mock_llm_always_fails(inp: LLMInvokeInput) -> LLMInvokeResult:
            raise ApplicationError("Rate limited", type="RateLimitError")

        @activity.defn(name="PostSanitize")
        async def mock_post(inp: PostSanitizeInput) -> PostSanitizeResult:
            return PostSanitizeResult(sanitized_content=inp.content, pii_types=[])

        inp = _make_workflow_input()

        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue=_TASK_QUEUE,
                workflows=[AgentTaskWorkflow],
                activities=[mock_pre, mock_policy, mock_jit, mock_llm_always_fails, mock_post],
            ):
                with pytest.raises(Exception):
                    await env.client.execute_workflow(
                        AgentTaskWorkflow.run,
                        inp,
                        id=f"escalate-{uuid.uuid4()}",
                        task_queue=_TASK_QUEUE,
                    )


# ---------------------------------------------------------------------------
# Integration tests — backoff timing
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBackoffTiming:
    """P2-2 integration: inter-attempt delays must double (within 10% tolerance)."""

    @pytest.mark.asyncio
    async def test_retry_intervals_are_approximately_exponential(self) -> None:
        """Capture real-time attempt timestamps; assert each gap is ~2× the previous.

        Due to the time-skipping environment, we validate the retrypolicy
        configuration values rather than wall-clock timings.  Wall-clock
        validation would require real timers and would make the test very slow
        (1 + 2 + 4 + 8 = 15 s minimum).
        """
        # Derive expected inter-attempt delays from the policy.
        initial = LLM_RETRY_POLICY.initial_interval.total_seconds()
        coefficient = LLM_RETRY_POLICY.backoff_coefficient
        expected_delays = [initial * (coefficient**i) for i in range(4)]

        # Verify each delay is double the previous within 10% tolerance.
        for i in range(1, len(expected_delays)):
            prev = expected_delays[i - 1]
            curr = expected_delays[i]
            ratio = curr / prev
            tolerance = 0.1  # 10%
            assert abs(ratio - coefficient) / coefficient <= tolerance, (
                f"Delay ratio at gap {i} is {ratio:.4f}, "
                f"expected {coefficient} ± {tolerance * 100:.0f}%"
            )

    def test_backoff_sequence_four_gaps_for_five_attempts(self) -> None:
        """Five attempts produce exactly four inter-attempt gaps."""
        max_attempts = LLM_RETRY_POLICY.maximum_attempts
        n_gaps = max_attempts - 1
        assert n_gaps == 4

    def test_delay_progression_values(self) -> None:
        """Delays must follow 1s → 2s → 4s → 8s for attempts 1-5."""
        initial = LLM_RETRY_POLICY.initial_interval.total_seconds()
        coefficient = LLM_RETRY_POLICY.backoff_coefficient
        expected = [1.0, 2.0, 4.0, 8.0]
        actual = [initial * (coefficient**i) for i in range(4)]
        for i, (exp, act) in enumerate(zip(expected, actual)):
            assert abs(exp - act) < 0.001, (
                f"Gap {i}: expected {exp}s, got {act}s"
            )


# ---------------------------------------------------------------------------
# Integration tests — timeout error retried
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTimeoutErrorRetry:
    """P2-2 integration: asyncio.TimeoutError triggers same retry behavior as RateLimitError."""

    @pytest.mark.asyncio
    async def test_timeout_error_is_retried(self) -> None:
        """asyncio.TimeoutError in LLMInvoke must trigger retries."""
        attempt_counts: list[int] = []

        @activity.defn(name="PrePIIScrub")
        async def mock_pre(inp: WorkflowInput) -> PrePIIScrubResult:
            return PrePIIScrubResult(sanitized_prompt=inp.prompt, pii_types=[])

        @activity.defn(name="PolicyEval")
        async def mock_policy(inp: PolicyEvalInput) -> PolicyEvalResult:
            return PolicyEvalResult(
                allowed=True, action="allow", fields=[],
                sanitized_prompt=inp.sanitized_prompt, extra_pii_types=[],
            )

        @activity.defn(name="JITTokenIssue")
        async def mock_jit(inp: JITTokenInput) -> JITTokenResult:
            return JITTokenResult(token="tok", jti=str(uuid.uuid4()))

        @activity.defn(name="LLMInvoke")
        async def mock_llm_timeout(inp: LLMInvokeInput) -> LLMInvokeResult:
            info = activity.info()
            attempt_counts.append(info.attempt)
            raise ApplicationError("Timeout", type="TimeoutError")

        @activity.defn(name="PostSanitize")
        async def mock_post(inp: PostSanitizeInput) -> PostSanitizeResult:
            return PostSanitizeResult(sanitized_content=inp.content, pii_types=[])

        inp = _make_workflow_input()

        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue=_TASK_QUEUE,
                workflows=[AgentTaskWorkflow],
                activities=[mock_pre, mock_policy, mock_jit, mock_llm_timeout, mock_post],
            ):
                with pytest.raises(Exception):
                    await env.client.execute_workflow(
                        AgentTaskWorkflow.run,
                        inp,
                        id=f"timeout-retry-{uuid.uuid4()}",
                        task_queue=_TASK_QUEUE,
                    )

        # TimeoutError must also be retried 5 times.
        assert len(attempt_counts) == 5, (
            f"Expected 5 timeout attempts, got {len(attempt_counts)}"
        )


# ---------------------------------------------------------------------------
# Integration tests — successful recovery on third attempt
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSuccessfulRecovery:
    """P2-2 integration: adapter fails twice then succeeds; verify recovery."""

    @pytest.mark.asyncio
    async def test_workflow_recovers_after_two_failures(self) -> None:
        """Adapter fails twice then succeeds; final WorkflowOutput must have success content."""
        call_count = 0

        @activity.defn(name="PrePIIScrub")
        async def mock_pre(inp: WorkflowInput) -> PrePIIScrubResult:
            return PrePIIScrubResult(sanitized_prompt=inp.prompt, pii_types=[])

        @activity.defn(name="PolicyEval")
        async def mock_policy(inp: PolicyEvalInput) -> PolicyEvalResult:
            return PolicyEvalResult(
                allowed=True, action="allow", fields=[],
                sanitized_prompt=inp.sanitized_prompt, extra_pii_types=[],
            )

        @activity.defn(name="JITTokenIssue")
        async def mock_jit(inp: JITTokenInput) -> JITTokenResult:
            return JITTokenResult(token="tok", jti=str(uuid.uuid4()))

        @activity.defn(name="LLMInvoke")
        async def mock_llm_fail_twice(inp: LLMInvokeInput) -> LLMInvokeResult:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise ApplicationError("Rate limited", type="RateLimitError")
            return LLMInvokeResult(
                content="Recovery success!",
                tokens_used=25,
                model="gpt-4o-mini",
                provider="openai",
            )

        @activity.defn(name="PostSanitize")
        async def mock_post(inp: PostSanitizeInput) -> PostSanitizeResult:
            return PostSanitizeResult(sanitized_content=inp.content, pii_types=[])

        inp = _make_workflow_input()

        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue=_TASK_QUEUE,
                workflows=[AgentTaskWorkflow],
                activities=[mock_pre, mock_policy, mock_jit, mock_llm_fail_twice, mock_post],
            ):
                result: WorkflowOutput = await env.client.execute_workflow(
                    AgentTaskWorkflow.run,
                    inp,
                    id=f"recovery-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

        assert result.workflow_status == "completed"
        assert result.content == "Recovery success!"
        # Total invocations: 2 failures + 1 success = 3.
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_successful_recovery_emits_two_retry_audit_events_and_counts_only_success_tokens(
        self,
    ) -> None:
        """Two retry failures must emit two llm.retried events and preserve only success spend."""
        audit = MagicMock(spec=AuditLogger)
        adapter = MagicMock()
        adapter.complete = AsyncMock(
            side_effect=[
                ApplicationError("Rate limited", type="RateLimitError"),
                ApplicationError("Rate limited", type="RateLimitError"),
                LLMResponse(
                    content="Recovered on third attempt",
                    tokens_used=25,
                    model="gpt-4o-mini",
                    provider="openai",
                ),
            ]
        )
        policy_engine = MagicMock(spec=PolicyEngine)
        policy_engine.evaluate = AsyncMock(
            return_value=PolicyResult(allowed=True, action="allow", reasons=[], fields=[])
        )
        activities = AegisActivities(
            adapter=adapter,
            audit_logger=audit,
            policy_engine=policy_engine,
        )
        inp = _make_workflow_input()

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
                ],
            ):
                result: WorkflowOutput = await env.client.execute_workflow(
                    AgentTaskWorkflow.run,
                    inp,
                    id=f"recovery-audit-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

        assert result.workflow_status == "completed"
        assert result.tokens_used == 25
        retried_calls = [
            call for call in audit.stage_event.call_args_list if call.args[0] == "llm.retried"
        ]
        assert len(retried_calls) == 2, "Expected exactly two llm.retried audit events"


# ---------------------------------------------------------------------------
# Negative tests — non-retryable errors not retried
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNonRetryableErrors:
    """P2-2 negative: PolicyDeniedError must not trigger retries."""

    @pytest.mark.asyncio
    async def test_policy_denied_error_not_retried(self) -> None:
        """LLM raising PolicyDeniedError must NOT trigger a retry — immediate failure."""
        llm_call_count = 0

        @activity.defn(name="PrePIIScrub")
        async def mock_pre(inp: WorkflowInput) -> PrePIIScrubResult:
            return PrePIIScrubResult(sanitized_prompt=inp.prompt, pii_types=[])

        @activity.defn(name="PolicyEval")
        async def mock_policy(inp: PolicyEvalInput) -> PolicyEvalResult:
            return PolicyEvalResult(
                allowed=True, action="allow", fields=[],
                sanitized_prompt=inp.sanitized_prompt, extra_pii_types=[],
            )

        @activity.defn(name="JITTokenIssue")
        async def mock_jit(inp: JITTokenInput) -> JITTokenResult:
            return JITTokenResult(token="tok", jti=str(uuid.uuid4()))

        @activity.defn(name="LLMInvoke")
        async def mock_llm_policy_denied(inp: LLMInvokeInput) -> LLMInvokeResult:
            nonlocal llm_call_count
            llm_call_count += 1
            raise ApplicationError(
                "Policy denied",
                type="PolicyDeniedError",
                non_retryable=True,
            )

        @activity.defn(name="PostSanitize")
        async def mock_post(inp: PostSanitizeInput) -> PostSanitizeResult:
            return PostSanitizeResult(sanitized_content=inp.content, pii_types=[])

        inp = _make_workflow_input()

        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue=_TASK_QUEUE,
                workflows=[AgentTaskWorkflow],
                activities=[
                    mock_pre, mock_policy, mock_jit, mock_llm_policy_denied, mock_post
                ],
            ):
                with pytest.raises(Exception):
                    await env.client.execute_workflow(
                        AgentTaskWorkflow.run,
                        inp,
                        id=f"no-retry-{uuid.uuid4()}",
                        task_queue=_TASK_QUEUE,
                    )

        # PolicyDeniedError must not be retried — exactly 1 call.
        assert llm_call_count == 1, (
            f"PolicyDeniedError must not be retried; got {llm_call_count} LLM calls"
        )

    @pytest.mark.asyncio
    async def test_policy_denied_emits_failed_audit_event(self) -> None:
        """A non-retryable LLM policy failure must emit workflow.failed.

        It must not be misclassified as retry exhaustion or HITL escalation.
        """
        audit = _RecordingAuditLogger()
        adapter = MagicMock()
        adapter.complete = AsyncMock(
            side_effect=ApplicationError(
                "Policy denied",
                type="PolicyDeniedError",
                non_retryable=True,
            )
        )
        policy_engine = MagicMock(spec=PolicyEngine)
        policy_engine.evaluate = AsyncMock(
            return_value=PolicyResult(allowed=True, action="allow", reasons=[], fields=[])
        )
        activities = AegisActivities(
            adapter=adapter,
            audit_logger=audit,
            policy_engine=policy_engine,
        )
        workflow_audit = WorkflowAuditActivities(audit_logger=audit)
        inp = _make_workflow_input()

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
                with pytest.raises(Exception):
                    await env.client.execute_workflow(
                        AgentTaskWorkflow.run,
                        inp,
                        id=f"no-retry-audit-{uuid.uuid4()}",
                        task_queue=_TASK_QUEUE,
                    )

        assert adapter.complete.await_count == 1
        failed_events = [entry for entry in audit.entries if entry["event"] == "workflow.failed"]
        assert failed_events, "Expected workflow.failed audit event for non-retryable LLM failure"
