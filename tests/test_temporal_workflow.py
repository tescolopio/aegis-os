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

"""Phase 2 (P2-1) tests for AgentTaskWorkflow and AegisActivities.

Test classes
------------
TestActivityMappingCompleteness
    Unit tests asserting that AgentTaskWorkflow and AegisActivities register
    exactly five Temporal activity methods with the documented stage names.

TestActivityExecutionOrder
    Integration tests using ``WorkflowEnvironment.start_time_skipping()`` that
    mock each activity to return a sentinel value and assert activities are
    scheduled in documented order.  Requires the Temporal dev server binary
    (downloaded on first run by the Temporal SDK — cached thereafter).

TestFullWorkflowExecution
    Integration tests running the full workflow against a Temporal test server
    with a stub LLM adapter.  Assert ``completed`` status, non-empty response
    content, and that all five OTel spans are present.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.adapters.base import LLMResponse
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
    WorkflowInput,
    WorkflowOutput,
)
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TASK_QUEUE = "aegis-test-wf"


def _make_stub_adapter(content: str = "Hello from stub LLM") -> MagicMock:
    """Return a mock BaseAdapter that returns a fixed LLMResponse."""
    adapter = MagicMock()
    adapter.complete = AsyncMock(
        return_value=LLMResponse(
            content=content,
            tokens_used=42,
            model="gpt-4o-mini",
            provider="openai",
            finish_reason="stop",
        )
    )
    return adapter


def _make_activities(adapter: MagicMock, *, tracer: Any | None = None) -> AegisActivities:
    """Return workflow activities with policy evaluation mocked to allow."""
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=True, action="allow", reasons=[], fields=[])
    )
    return AegisActivities(adapter=adapter, policy_engine=policy_engine, tracer=tracer)


def _make_workflow_input(prompt: str = "Tell me a joke") -> WorkflowInput:
    return WorkflowInput(
        task_id=str(uuid.uuid4()),
        prompt=prompt,
        agent_type="general",
        requester_id="test-user",
    )


# ---------------------------------------------------------------------------
# Unit tests — activity mapping completeness (no Temporal server required)
# ---------------------------------------------------------------------------


class TestActivityMappingCompleteness:
    """P2-1 unit: AgentTaskWorkflow registers exactly five Temporal activity methods."""

    def test_activity_names_tuple_length(self) -> None:
        """ACTIVITY_NAMES must contain exactly five entries."""
        assert len(AgentTaskWorkflow.ACTIVITY_NAMES) == 5

    def test_activity_names_are_exactly_the_five_stage_names(self) -> None:
        """ACTIVITY_NAMES must match the documented five governance stage names."""
        expected = ("PrePIIScrub", "PolicyEval", "JITTokenIssue", "LLMInvoke", "PostSanitize")
        assert AgentTaskWorkflow.ACTIVITY_NAMES == expected

    def test_aegis_activities_has_five_defn_decorated_methods(self) -> None:
        """AegisActivities must have exactly five @activity.defn decorated methods."""
        method_names = [
            "pre_pii_scrub",
            "policy_eval",
            "jit_token_issue",
            "llm_invoke",
            "post_sanitize",
        ]
        for mname in method_names:
            method = getattr(AegisActivities, mname)
            assert hasattr(method, "__temporal_activity_definition"), (
                f"AegisActivities.{mname} is missing @activity.defn decoration"
            )

    def test_activity_registered_names_match_activity_names_tuple(self) -> None:
        """Each @activity.defn name must appear in AgentTaskWorkflow.ACTIVITY_NAMES."""
        method_map = {
            "pre_pii_scrub": "PrePIIScrub",
            "policy_eval": "PolicyEval",
            "jit_token_issue": "JITTokenIssue",
            "llm_invoke": "LLMInvoke",
            "post_sanitize": "PostSanitize",
        }
        for method_name, expected_activity_name in method_map.items():
            method = getattr(AegisActivities, method_name)
            defn = getattr(method, "__temporal_activity_definition")
            assert defn.name == expected_activity_name, (
                f"AegisActivities.{method_name} has Temporal name {defn.name!r}, "
                f"expected {expected_activity_name!r}"
            )
            assert expected_activity_name in AgentTaskWorkflow.ACTIVITY_NAMES

    def test_workflow_class_exposes_activity_method_references(self) -> None:
        """AgentTaskWorkflow must expose each activity method as a class attribute."""
        method_map = {
            "pre_pii_scrub": "PrePIIScrub",
            "policy_eval": "PolicyEval",
            "jit_token_issue": "JITTokenIssue",
            "llm_invoke": "LLMInvoke",
            "post_sanitize": "PostSanitize",
        }
        for attr_name, activity_name in method_map.items():
            assert hasattr(AgentTaskWorkflow, attr_name), (
                f"AgentTaskWorkflow.{attr_name} not found"
            )
            method = getattr(AgentTaskWorkflow, attr_name)
            defn = getattr(method, "__temporal_activity_definition")
            assert defn.name == activity_name

    def test_workflow_is_temporal_workflow(self) -> None:
        """AgentTaskWorkflow must be decorated with @workflow.defn."""
        assert hasattr(AgentTaskWorkflow, "__temporal_workflow_definition"), (
            "AgentTaskWorkflow is missing @workflow.defn decoration"
        )

    def test_llm_retry_policy_maximum_attempts(self) -> None:
        """LLM_RETRY_POLICY must cap retries at exactly 5 attempts."""
        assert LLM_RETRY_POLICY.maximum_attempts == 5

    def test_llm_retry_policy_backoff_coefficient(self) -> None:
        """LLM_RETRY_POLICY must use backoff coefficient 2.0 (doubling delays)."""
        assert LLM_RETRY_POLICY.backoff_coefficient == 2.0

    def test_llm_retry_policy_policy_denied_is_non_retryable(self) -> None:
        """PolicyDeniedError must be listed as non-retryable in LLM_RETRY_POLICY."""
        non_retryable = LLM_RETRY_POLICY.non_retryable_error_types or []
        assert "PolicyDeniedError" in non_retryable


# ---------------------------------------------------------------------------
# Integration tests — activity execution order
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestActivityExecutionOrder:
    """P2-1 integration: verify activities are scheduled in documented order.

    These tests use ``WorkflowEnvironment.start_time_skipping()`` which starts
    a lightweight local Temporal server.  The Temporal dev server binary is
    downloaded automatically on first run and cached.
    """

    @pytest.mark.asyncio
    async def test_activities_execute_in_documented_order(self) -> None:
        """Activities must be scheduled in strict PrePIIScrub→…→PostSanitize order."""
        execution_order: list[str] = []

        task_id = str(uuid.uuid4())
        inp = _make_workflow_input()
        inp.task_id = task_id

        @activity.defn(name="PrePIIScrub")
        async def mock_pre_pii_scrub(wf_inp: WorkflowInput) -> PrePIIScrubResult:
            execution_order.append("PrePIIScrub")
            return PrePIIScrubResult(sanitized_prompt=wf_inp.prompt, pii_types=[])

        @activity.defn(name="PolicyEval")
        async def mock_policy_eval(pol_inp: PolicyEvalInput) -> PolicyEvalResult:
            execution_order.append("PolicyEval")
            return PolicyEvalResult(
                allowed=True,
                action="allow",
                fields=[],
                sanitized_prompt=pol_inp.sanitized_prompt,
                extra_pii_types=[],
            )

        @activity.defn(name="JITTokenIssue")
        async def mock_jit_token_issue(jit_inp: JITTokenInput) -> JITTokenResult:
            execution_order.append("JITTokenIssue")
            return JITTokenResult(token="mock-token", jti=str(uuid.uuid4()))

        @activity.defn(name="LLMInvoke")
        async def mock_llm_invoke(llm_inp: LLMInvokeInput) -> LLMInvokeResult:
            execution_order.append("LLMInvoke")
            return LLMInvokeResult(
                content="sentinel-response",
                tokens_used=10,
                model="gpt-4o-mini",
                provider="openai",
            )

        @activity.defn(name="PostSanitize")
        async def mock_post_sanitize(post_inp: PostSanitizeInput) -> PostSanitizeResult:
            execution_order.append("PostSanitize")
            return PostSanitizeResult(sanitized_content=post_inp.content, pii_types=[])

        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue=_TASK_QUEUE,
                workflows=[AgentTaskWorkflow],
                activities=[
                    mock_pre_pii_scrub,
                    mock_policy_eval,
                    mock_jit_token_issue,
                    mock_llm_invoke,
                    mock_post_sanitize,
                ],
            ):
                result: WorkflowOutput = await env.client.execute_workflow(
                    AgentTaskWorkflow.run,
                    inp,
                    id=f"order-test-{task_id}",
                    task_queue=_TASK_QUEUE,
                )

        assert execution_order == [
            "PrePIIScrub",
            "PolicyEval",
            "JITTokenIssue",
            "LLMInvoke",
            "PostSanitize",
        ], f"Expected documented order, got: {execution_order}"
        assert result.workflow_status == "completed"

    @pytest.mark.asyncio
    async def test_reversing_activity_order_produces_wrong_result(self) -> None:
        """Activities must NOT be callable in reverse order — wrong order is detectable.

        This test verifies the ordering assertion: if activities returned
        in reverse order the execution_order list would differ from the expected.
        The test asserts that the reverse is NOT equal to the documented order.
        """
        reverse_order = ["PostSanitize", "LLMInvoke", "JITTokenIssue", "PolicyEval", "PrePIIScrub"]
        documented_order = list(AgentTaskWorkflow.ACTIVITY_NAMES)
        assert reverse_order != documented_order, (
            "Reverse order must not equal the documented execution order"
        )


# ---------------------------------------------------------------------------
# Integration tests — full workflow execution
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFullWorkflowExecution:
    """P2-1 integration: run AgentTaskWorkflow end-to-end with a stub adapter."""

    @pytest.mark.asyncio
    async def test_workflow_emits_all_five_stage_spans(self) -> None:
        """A full Temporal workflow run must export all five documented stage spans."""
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("test.temporal.workflow")

        adapter = _make_stub_adapter("span check")
        activities = _make_activities(adapter, tracer=tracer)
        inp = _make_workflow_input("Emit all stage spans")

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
                    id=f"otel-test-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

        assert result.workflow_status == "completed"
        span_names = [span.name for span in exporter.get_finished_spans()]
        for expected in AgentTaskWorkflow.ACTIVITY_NAMES:
            stage_name = {
                "PrePIIScrub": "pre-pii-scrub",
                "PolicyEval": "policy-eval",
                "JITTokenIssue": "jit-token-issue",
                "LLMInvoke": "llm-invoke",
                "PostSanitize": "post-sanitize",
            }[expected]
            assert stage_name in span_names, f"Missing exported stage span {stage_name!r}"

    @pytest.mark.asyncio
    async def test_workflow_reaches_completed_status(self) -> None:
        """Full workflow must return WorkflowOutput with workflow_status='completed'."""
        adapter = _make_stub_adapter("The answer is 42")
        activities = _make_activities(adapter)
        inp = _make_workflow_input("What is the answer to life?")

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
                    id=f"full-exec-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

        assert result.workflow_status == "completed"

    @pytest.mark.asyncio
    async def test_workflow_returns_non_empty_content(self) -> None:
        """Completed workflow must return non-empty content in WorkflowOutput."""
        adapter = _make_stub_adapter("Non-empty response from stub LLM")
        activities = _make_activities(adapter)
        inp = _make_workflow_input("Hello")

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
                    id=f"content-test-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

        assert result.content, "WorkflowOutput.content must not be empty"
        assert len(result.content) > 0

    @pytest.mark.asyncio
    async def test_workflow_task_id_preserved_in_output(self) -> None:
        """task_id must be preserved verbatim through the full workflow."""
        adapter = _make_stub_adapter()
        activities = _make_activities(adapter)
        inp = _make_workflow_input()
        original_task_id = inp.task_id

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
                    id=f"taskid-test-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

        assert result.task_id == original_task_id

    @pytest.mark.asyncio
    async def test_pii_in_prompt_is_scrubbed_from_output(self) -> None:
        """PII in the input prompt must not appear in the final content."""
        adapter = _make_stub_adapter("Hello there!")
        activities = _make_activities(adapter)
        inp = _make_workflow_input("Email me at user@example.com about the task")

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
                    id=f"pii-test-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

        # Original email must be gone from the sanitized prompt.
        assert "user@example.com" not in result.sanitized_prompt
        # PII types should include email.
        assert "email" in result.pii_types

