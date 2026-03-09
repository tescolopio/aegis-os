"""W2-4 replay regression for seeded multi-task Temporal recovery."""

from __future__ import annotations

import asyncio
import os
import random
import time
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import Any, cast
from uuid import uuid4

import pytest
from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.adapters.base import BaseAdapter, LLMResponse
from src.audit_vault.logger import AuditLogger, LifecycleEvent
from src.control_plane.scheduler import (
    AegisActivities,
    BudgetPreCheckInput,
    BudgetPreCheckResult,
    BudgetRecordInput,
    BudgetRecordResult,
    JITTokenInput,
    JITTokenResult,
    LLMInvokeInput,
    LLMInvokeResult,
    PendingApprovalState,
    PolicyEvalInput,
    PolicyEvalResult,
    PostSanitizeInput,
    PostSanitizeResult,
    PrePIIScrubResult,
    WorkflowInput,
    WorkflowOutput,
)
from src.governance.policy_engine.opa_client import PolicyEngine, PolicyResult
from src.governance.session_mgr import SessionManager
from src.watchdog.budget_enforcer import BudgetEnforcer

_TASK_QUEUE = "aegis-budget-replay"
_REPLAY_TASK_COUNT = int(os.environ.get("AEGIS_REPLAY_TASK_COUNT", "1000"))
_REPLAY_BATCH_SIZE = int(os.environ.get("AEGIS_REPLAY_BATCH_SIZE", "1"))
_PERFORMANCE_BUDGET_SECONDS = 300.0
_COST_PER_TOKEN_USD = BudgetEnforcer.DEFAULT_COST_PER_TOKEN
_STAGE_NAMES = ["PrePIIScrub", "PolicyEval", "JITTokenIssue", "LLMInvoke", "PostSanitize"]
_FAST_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(milliseconds=1),
    backoff_coefficient=1.0,
    maximum_interval=timedelta(milliseconds=1),
    maximum_attempts=2,
)


@dataclass(frozen=True)
class ReplayTaskSpec:
    """Seed-derived replay configuration for a single workflow run."""

    task_id: str
    budget_session_id: str
    prompt: str
    tokens_used: int
    injected_stage: str
    expected_spend_usd: str


class _ReplayAuditLogger:
    """Collect structured audit records for replay reconciliation assertions."""

    def __init__(self, sink: list[dict[str, Any]], cost_per_token_usd: Decimal) -> None:
        self._sink = sink
        self._cost_per_token_usd = cost_per_token_usd

    def info(self, event: str, **kwargs: object) -> None:
        self._sink.append({"event": event, **kwargs})

    def warning(self, event: str, **kwargs: object) -> None:
        self._sink.append({"event": event, **kwargs})

    def error(self, event: str, **kwargs: object) -> None:
        self._sink.append({"event": event, **kwargs})

    def stage_event(
        self,
        event: str,
        *,
        outcome: str,
        stage: str,
        task_id: str,
        agent_type: str,
        **kwargs: object,
    ) -> None:
        record: dict[str, Any] = {
            "event": "llm.invoke.completed" if event == "llm.completed" else event,
            "outcome": outcome,
            "stage": stage,
            "task_id": task_id,
            "agent_type": agent_type,
            **kwargs,
        }
        tokens_used = kwargs.get("tokens_used")
        if isinstance(tokens_used, int):
            record["token_cost_usd"] = str(Decimal(tokens_used) * self._cost_per_token_usd)
        self._sink.append(record)

    def lifecycle_event(
        self,
        event: str,
        *,
        event_type: str,
        task_id: str,
        agent_type: str,
        session_id: str | None,
        workflow_status: str,
        stage: str = "workflow-lifecycle",
        **kwargs: object,
    ) -> None:
        self._sink.append(
            {
                "event": event,
                "event_type": event_type,
                "task_id": task_id,
                "agent_type": agent_type,
                "session_id": session_id or "",
                "workflow_status": workflow_status,
                "stage": stage,
                **kwargs,
            }
        )


class _AllowPolicyEngine:
    """Async allow-all policy stub for replay workflows."""

    async def evaluate(self, *_args: Any, **_kwargs: Any) -> PolicyResult:
        return PolicyResult(allowed=True, action="allow", reasons=[], fields=[])


class _ReplayAdapter(BaseAdapter):
    """Prompt-indexed adapter stub used to vary cost across replay tasks."""

    def __init__(self, specs_by_prompt: dict[str, ReplayTaskSpec]) -> None:
        self._specs_by_prompt = specs_by_prompt

    @property
    def provider_name(self) -> str:
        return "budget-replay-adapter"

    async def complete(self, request: object) -> LLMResponse:
        prompt = getattr(request, "prompt")
        if not isinstance(prompt, str):
            raise TypeError("Replay adapter expected an LLMRequest-like object with a prompt")
        spec = self._specs_by_prompt[prompt]
        return LLMResponse(
            content=f"replay-ok:{spec.task_id}",
            tokens_used=spec.tokens_used,
            model="gpt-4o-mini",
            provider=self.provider_name,
            finish_reason="stop",
        )


@workflow.defn(name="BudgetReplayWorkflow", sandboxed=False)
class BudgetReplayWorkflow:
    """Workflow exercising replay-safe budget accounting with fast retries."""

    @workflow.run
    async def run(self, inp: WorkflowInput) -> WorkflowOutput:
        budget_spent_usd: str | None = None
        scrub_result: PrePIIScrubResult = await workflow.execute_activity(
            "PrePIIScrub",
            inp,
            result_type=PrePIIScrubResult,
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=_FAST_RETRY_POLICY,
        )
        policy_result: PolicyEvalResult = await workflow.execute_activity(
            "PolicyEval",
            PolicyEvalInput(
                task_id=inp.task_id,
                sanitized_prompt=scrub_result.sanitized_prompt,
                agent_type=inp.agent_type,
                requester_id=inp.requester_id,
                model=inp.model,
            ),
            result_type=PolicyEvalResult,
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=_FAST_RETRY_POLICY,
        )
        await workflow.execute_activity(
            "BudgetPreCheck",
            BudgetPreCheckInput(
                task_id=inp.task_id,
                agent_type=inp.agent_type,
                budget_session_id=cast(str, inp.budget_session_id),
                budget_limit_usd=cast(str, inp.budget_limit_usd),
                history=[],
            ),
            result_type=BudgetPreCheckResult,
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
        token_result: JITTokenResult = await workflow.execute_activity(
            "JITTokenIssue",
            JITTokenInput(
                agent_type=inp.agent_type,
                requester_id=inp.requester_id,
                task_id=inp.task_id,
                protect_outbound_request=inp.protect_outbound_request,
                session_id=inp.session_id,
                allowed_actions=("llm:complete",),
                rotation_key=f"replay:{inp.task_id}",
            ),
            result_type=JITTokenResult,
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=_FAST_RETRY_POLICY,
        )
        llm_result: LLMInvokeResult = await workflow.execute_activity(
            "LLMInvoke",
            LLMInvokeInput(
                task_id=inp.task_id,
                sanitized_prompt=policy_result.sanitized_prompt,
                agent_type=inp.agent_type,
                requester_id=inp.requester_id,
                token=token_result.token,
                model=inp.model,
                max_tokens=inp.max_tokens,
                temperature=inp.temperature,
                system_prompt=inp.system_prompt,
                protect_outbound_request=inp.protect_outbound_request,
                session_id=inp.session_id,
                allowed_actions=("llm:complete",),
                rotation_key=f"replay:{inp.task_id}",
            ),
            result_type=LLMInvokeResult,
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=_FAST_RETRY_POLICY,
        )
        budget_record_result: BudgetRecordResult = await workflow.execute_activity(
            "BudgetRecordSpend",
            BudgetRecordInput(
                task_id=inp.task_id,
                agent_type=inp.agent_type,
                budget_session_id=cast(str, inp.budget_session_id),
                budget_limit_usd=cast(str, inp.budget_limit_usd),
                tokens_used=llm_result.tokens_used,
                cost_per_token_usd=inp.cost_per_token_usd,
                history=[],
            ),
            result_type=BudgetRecordResult,
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
        budget_spent_usd = budget_record_result.snapshot["cost_usd"]
        post_result: PostSanitizeResult = await workflow.execute_activity(
            "PostSanitize",
            PostSanitizeInput(
                task_id=inp.task_id,
                agent_type=inp.agent_type,
                content=llm_result.content,
                tokens_used=llm_result.tokens_used,
                model=llm_result.model,
                provider=llm_result.provider,
            ),
            result_type=PostSanitizeResult,
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=_FAST_RETRY_POLICY,
        )
        return WorkflowOutput(
            task_id=inp.task_id,
            content=post_result.sanitized_content,
            sanitized_prompt=policy_result.sanitized_prompt,
            pii_types=list(scrub_result.pii_types) + list(policy_result.extra_pii_types),
            tokens_used=llm_result.tokens_used,
            model=llm_result.model,
            workflow_status="completed",
            approval_state=PendingApprovalState.NOT_REQUIRED.value,
            budget_spent_usd=budget_spent_usd,
        )


def _replay_seed() -> int:
    raw = os.environ.get("AEGIS_REPLAY_SEED", "20260308")
    return int(raw)


def _build_task_specs(task_count: int) -> list[ReplayTaskSpec]:
    rng = random.Random(_replay_seed())
    specs: list[ReplayTaskSpec] = []
    for index in range(task_count):
        task_id = str(uuid4())
        tokens_used = rng.randint(100, 5000)
        injected_stage = rng.choice(_STAGE_NAMES)
        specs.append(
            ReplayTaskSpec(
                task_id=task_id,
                budget_session_id=str(uuid4()),
                prompt=f"Budget replay prompt item {index}",
                tokens_used=tokens_used,
                injected_stage=injected_stage,
                expected_spend_usd=str(Decimal(tokens_used) * _COST_PER_TOKEN_USD),
            )
        )
    return specs


@pytest.mark.integration
@pytest.mark.asyncio
async def test_budget_replay_seeded_1000_tasks_have_exact_spend_and_retry_audit() -> None:
    specs = _build_task_specs(_REPLAY_TASK_COUNT)
    specs_by_task_id = {spec.task_id: spec for spec in specs}
    specs_by_prompt = {spec.prompt: spec for spec in specs}
    audit_events: list[dict[str, Any]] = []
    failure_injected: set[tuple[str, str]] = set()
    audit_logger = _ReplayAuditLogger(audit_events, _COST_PER_TOKEN_USD)
    policy_engine = cast(PolicyEngine, _AllowPolicyEngine())
    activities = AegisActivities(
        adapter=_ReplayAdapter(specs_by_prompt),
        policy_engine=policy_engine,
        session_mgr=SessionManager(),
        budget_enforcer=BudgetEnforcer(audit_logger=cast(AuditLogger, audit_logger)),
        audit_logger=cast(AuditLogger, audit_logger),
    )

    def _maybe_fail(task_id: str, stage_name: str) -> None:
        spec = specs_by_task_id[task_id]
        key = (task_id, stage_name)
        if spec.injected_stage == stage_name and key not in failure_injected:
            failure_injected.add(key)
            audit_events.append(
                {
                    "event": LifecycleEvent.RETRIED.value,
                    "task_id": task_id,
                    "stage": stage_name,
                    "injected": True,
                }
            )
            raise RuntimeError(f"Injected replay failure at {stage_name} for {task_id}")

    @activity.defn(name="PrePIIScrub")
    async def _pre_pii_scrub(inp: WorkflowInput) -> PrePIIScrubResult:
        _maybe_fail(inp.task_id, "PrePIIScrub")
        return await activities.pre_pii_scrub(inp)

    @activity.defn(name="PolicyEval")
    async def _policy_eval(inp: PolicyEvalInput) -> PolicyEvalResult:
        _maybe_fail(inp.task_id, "PolicyEval")
        return await activities.policy_eval(inp)

    @activity.defn(name="BudgetPreCheck")
    async def _budget_pre_check(inp: BudgetPreCheckInput) -> BudgetPreCheckResult:
        return await activities.budget_pre_check(inp)

    @activity.defn(name="JITTokenIssue")
    async def _jit_token_issue(inp: JITTokenInput) -> JITTokenResult:
        _maybe_fail(inp.task_id, "JITTokenIssue")
        return await activities.jit_token_issue(inp)

    @activity.defn(name="LLMInvoke")
    async def _llm_invoke(inp: LLMInvokeInput) -> LLMInvokeResult:
        _maybe_fail(inp.task_id, "LLMInvoke")
        return await activities.llm_invoke(inp)

    @activity.defn(name="BudgetRecordSpend")
    async def _budget_record_spend(inp: BudgetRecordInput) -> BudgetRecordResult:
        return await activities.budget_record_spend(inp)

    @activity.defn(name="PostSanitize")
    async def _post_sanitize(inp: PostSanitizeInput) -> PostSanitizeResult:
        _maybe_fail(inp.task_id, "PostSanitize")
        return await activities.post_sanitize(inp)

    workflow_inputs = [
        WorkflowInput(
            task_id=spec.task_id,
            prompt=spec.prompt,
            agent_type="finance",
            requester_id="budget-replay-user",
            budget_session_id=spec.budget_session_id,
            budget_limit_usd="1000.00",
            cost_per_token_usd=str(_COST_PER_TOKEN_USD),
        )
        for spec in specs
    ]

    started = time.monotonic()
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=_TASK_QUEUE,
            workflows=[BudgetReplayWorkflow],
            activities=[
                _pre_pii_scrub,
                _policy_eval,
                _budget_pre_check,
                _jit_token_issue,
                _llm_invoke,
                _budget_record_spend,
                _post_sanitize,
            ],
        ):
            results: list[WorkflowOutput] = []
            for start_index in range(0, len(workflow_inputs), _REPLAY_BATCH_SIZE):
                batch = workflow_inputs[start_index : start_index + _REPLAY_BATCH_SIZE]
                handles = [
                    await env.client.start_workflow(
                        BudgetReplayWorkflow.run,
                        workflow_input,
                        id=f"budget-replay-{workflow_input.task_id}",
                        task_queue=_TASK_QUEUE,
                    )
                    for workflow_input in batch
                ]
                results.extend(await asyncio.gather(*(handle.result() for handle in handles)))
    elapsed = time.monotonic() - started

    per_task_events: dict[str, list[dict[str, Any]]] = {}
    for event in audit_events:
        task_id = event.get("task_id")
        if isinstance(task_id, str):
            per_task_events.setdefault(task_id, []).append(event)

    total_budget_spend = Decimal("0")
    for result in results:
        spec = specs_by_task_id[result.task_id]
        task_events = per_task_events[result.task_id]
        assert result.workflow_status == "completed"
        assert result.budget_spent_usd == spec.expected_spend_usd
        per_task_audit_total = sum(
            (
                Decimal(cast(str, event["token_cost_usd"]))
                for event in task_events
                if event.get("event") == "llm.invoke.completed"
            ),
            Decimal("0"),
        )
        assert per_task_audit_total == Decimal(spec.expected_spend_usd)
        assert result.budget_spent_usd is not None
        total_budget_spend += Decimal(result.budget_spent_usd)
        task_event_names = [cast(str, event["event"]) for event in task_events]
        assert LifecycleEvent.RETRIED.value in task_event_names
        task_events.append(
            {
                "event": LifecycleEvent.COMPLETED.value,
                "task_id": result.task_id,
                "workflow_status": result.workflow_status,
            }
        )
        completed_index = next(
            index
            for index, event in enumerate(task_events)
            if event.get("event") == LifecycleEvent.COMPLETED.value
        )
        retried_indices = [
            index
            for index, event in enumerate(task_events)
            if event.get("event") == LifecycleEvent.RETRIED.value
        ]
        assert retried_indices
        assert max(retried_indices) < completed_index

    total_audit_spend = sum(
        (
            Decimal(cast(str, event["token_cost_usd"]))
            for event in audit_events
            if event.get("event") == "llm.invoke.completed"
        ),
        Decimal("0"),
    )
    assert total_audit_spend.quantize(Decimal("0.0001")) == total_budget_spend.quantize(
        Decimal("0.0001")
    )
    assert elapsed < _PERFORMANCE_BUDGET_SECONDS, (
        f"Replay run took {elapsed:.2f}s; must stay under {_PERFORMANCE_BUDGET_SECONDS:.0f}s"
    )
