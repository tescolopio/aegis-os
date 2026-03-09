"""W2-1 tests for durable budget recovery in Temporal workflows."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import threading
from decimal import Decimal
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from temporalio import activity
from temporalio.client import Client
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.adapters.base import BaseAdapter, LLMResponse
from src.audit_vault.logger import AuditLogger
from src.control_plane.scheduler import (
    AegisActivities,
    AgentTaskWorkflow,
    BudgetPreCheckInput,
    BudgetPreCheckResult,
    BudgetRecordInput,
    BudgetRecordResult,
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
from src.governance.session_mgr import SessionManager
from src.watchdog.budget_enforcer import BudgetEnforcer

_TASK_QUEUE = "aegis-budget-recovery"
_RECOVERY_TIMEOUT_SECONDS = 10.0
_GOVERNANCE_STAGE_NAMES = [
    "PrePIIScrub",
    "PolicyEval",
    "JITTokenIssue",
    "LLMInvoke",
    "PostSanitize",
]
_MP_CONTEXT = multiprocessing.get_context("spawn")


class _BudgetAdapter(BaseAdapter):
    """Stub adapter with a fixed token count for budget accounting tests."""

    def __init__(self, *, tokens_used: int = 1500, content: str = "budget-ok") -> None:
        self._tokens_used = tokens_used
        self._content = content

    @property
    def provider_name(self) -> str:
        return "budget-adapter"

    async def complete(self, request: object) -> LLMResponse:
        return LLMResponse(
            content=self._content,
            tokens_used=self._tokens_used,
            model="gpt-4o-mini",
            provider=self.provider_name,
            finish_reason="stop",
        )


def _make_activities(*, tokens_used: int = 1500) -> AegisActivities:
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate = AsyncMock(
        return_value=PolicyResult(allowed=True, action="allow", reasons=[], fields=[])
    )
    return AegisActivities(
        adapter=_BudgetAdapter(tokens_used=tokens_used),
        policy_engine=policy_engine,
        session_mgr=SessionManager(),
        audit_logger=MagicMock(spec=AuditLogger),
    )


def _get_temporal_target_host(env: WorkflowEnvironment) -> str:
    """Return the Temporal dev server target host across SDK config shapes."""
    config = env.client.config()
    if isinstance(config, dict):
        target_host = config.get("target_host")
        if isinstance(target_host, str) and target_host:
            return target_host
    return env.client.service_client.config.target_host


def _schedule_worker_exit() -> None:
    """Exit shortly after returning so Temporal can persist the activity result."""
    threading.Timer(1.0, os._exit, args=(1,)).start()


def _run_budget_worker(
    target_host: str,
    die_after_stage: str | None,
    completion_counts: dict[str, Any],
    ready_event: Any,
    stage_done_events: dict[str, Any],
) -> None:
    """Run a subprocess worker that executes budget-aware workflow activities."""

    class _AllowPolicyEngine:
        async def evaluate(self, *_args: Any, **_kwargs: Any) -> PolicyResult:
            return PolicyResult(allowed=True, action="allow", reasons=[], fields=[])

    class _SubprocessAdapter(BaseAdapter):
        @property
        def provider_name(self) -> str:
            return "budget-chaos-adapter"

        async def complete(self, request: object) -> LLMResponse:
            return LLMResponse(
                content="budget-chaos-ok",
                tokens_used=1500,
                model="gpt-4o-mini",
                provider=self.provider_name,
                finish_reason="stop",
            )

    async def _main() -> None:
        client = await Client.connect(target_host)
        session_mgr = SessionManager()
        budget_enforcer = BudgetEnforcer()
        adapter = _SubprocessAdapter()
        activities = AegisActivities(
            adapter=adapter,
            policy_engine=cast(PolicyEngine, _AllowPolicyEngine()),
            session_mgr=session_mgr,
            budget_enforcer=budget_enforcer,
            audit_logger=AuditLogger("budget-chaos-worker"),
        )

        @activity.defn(name="PrePIIScrub")
        async def _pre_pii_scrub(inp: WorkflowInput) -> PrePIIScrubResult:
            result = await activities.pre_pii_scrub(inp)
            completion_counts["PrePIIScrub"] = completion_counts.get("PrePIIScrub", 0) + 1
            stage_done_events["PrePIIScrub"].set()
            if die_after_stage == "PrePIIScrub":
                _schedule_worker_exit()
            return result

        @activity.defn(name="PolicyEval")
        async def _policy_eval(inp: PolicyEvalInput) -> PolicyEvalResult:
            result = await activities.policy_eval(inp)
            completion_counts["PolicyEval"] = completion_counts.get("PolicyEval", 0) + 1
            stage_done_events["PolicyEval"].set()
            if die_after_stage == "PolicyEval":
                _schedule_worker_exit()
            return result

        @activity.defn(name="BudgetPreCheck")
        async def _budget_pre_check(inp: BudgetPreCheckInput) -> BudgetPreCheckResult:
            result = await activities.budget_pre_check(inp)
            completion_counts["BudgetPreCheck"] = completion_counts.get("BudgetPreCheck", 0) + 1
            return result

        @activity.defn(name="JITTokenIssue")
        async def _jit_token_issue(inp: JITTokenInput) -> JITTokenResult:
            result = await activities.jit_token_issue(inp)
            completion_counts["JITTokenIssue"] = completion_counts.get("JITTokenIssue", 0) + 1
            stage_done_events["JITTokenIssue"].set()
            if die_after_stage == "JITTokenIssue":
                _schedule_worker_exit()
            return result

        @activity.defn(name="LLMInvoke")
        async def _llm_invoke(inp: LLMInvokeInput) -> LLMInvokeResult:
            result = await activities.llm_invoke(inp)
            completion_counts["LLMInvoke"] = completion_counts.get("LLMInvoke", 0) + 1
            stage_done_events["LLMInvoke"].set()
            if die_after_stage == "LLMInvoke":
                _schedule_worker_exit()
            return result

        @activity.defn(name="BudgetRecordSpend")
        async def _budget_record_spend(inp: BudgetRecordInput) -> BudgetRecordResult:
            result = await activities.budget_record_spend(inp)
            completion_counts["BudgetRecordSpend"] = (
                completion_counts.get("BudgetRecordSpend", 0) + 1
            )
            return result

        @activity.defn(name="PostSanitize")
        async def _post_sanitize(inp: PostSanitizeInput) -> PostSanitizeResult:
            result = await activities.post_sanitize(inp)
            completion_counts["PostSanitize"] = completion_counts.get("PostSanitize", 0) + 1
            stage_done_events["PostSanitize"].set()
            if die_after_stage == "PostSanitize":
                _schedule_worker_exit()
            return result

        ready_event.set()
        async with Worker(
            client,
            task_queue=_TASK_QUEUE,
            workflows=[AgentTaskWorkflow],
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
            await asyncio.sleep(60)

    asyncio.run(_main())


def _start_budget_worker_process(
    target_host: str,
    die_after_stage: str | None,
    manager: multiprocessing.managers.SyncManager,
) -> tuple[Any, Any, Any, Any]:
    """Start a budget-aware worker subprocess and return the shared state handles."""
    completion_counts: Any = manager.dict()
    ready_event = manager.Event()
    stage_done_events: dict[str, Any] = {
        name: manager.Event() for name in _GOVERNANCE_STAGE_NAMES
    }
    proc = _MP_CONTEXT.Process(
        target=_run_budget_worker,
        args=(target_host, die_after_stage, completion_counts, ready_event, stage_done_events),
        daemon=True,
    )
    proc.start()
    return proc, completion_counts, ready_event, stage_done_events


@pytest.mark.asyncio
async def test_budget_pre_check_restores_exact_spend_from_history() -> None:
    activities = _make_activities()
    budget_session_id = str(uuid4())

    result = await activities.budget_pre_check(
        BudgetPreCheckInput(
            task_id="budget-task",
            agent_type="finance",
            budget_session_id=budget_session_id,
            budget_limit_usd="10.00",
            history=[
                {"operation_id": "activity-1", "amount_usd": "1.00", "tokens_used": 500000},
                {"operation_id": "activity-2", "amount_usd": "2.00", "tokens_used": 1000000},
            ],
        )
    )

    assert result.snapshot["cost_usd"] == "3.000000"
    assert result.snapshot["tokens_used"] == 1500000


@pytest.mark.asyncio
async def test_budget_record_spend_uses_activity_id_for_idempotent_redelivery() -> None:
    activities = _make_activities(tokens_used=500000)
    budget_session_id = str(uuid4())
    activity_info = MagicMock()
    activity_info.activity_id = "7"
    activity_info.workflow_id = "budget-workflow"

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(activity, "info", lambda: activity_info)
        first = await activities.budget_record_spend(
            BudgetRecordInput(
                task_id="budget-task",
                agent_type="finance",
                budget_session_id=budget_session_id,
                budget_limit_usd="10.00",
                tokens_used=500000,
                cost_per_token_usd="0.000002",
                history=[],
            )
        )
        second = await activities.budget_record_spend(
            BudgetRecordInput(
                task_id="budget-task",
                agent_type="finance",
                budget_session_id=budget_session_id,
                budget_limit_usd="10.00",
                tokens_used=500000,
                cost_per_token_usd="0.000002",
                history=first.history,
            )
        )

    assert first.snapshot["cost_usd"] == "1.000000"
    assert second.snapshot["cost_usd"] == "1.000000"
    assert len(second.history) == 1
    assert second.history[0]["operation_id"] == "budget-workflow:7"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_workflow_surfaces_exact_budget_spend_from_durable_history() -> None:
    activities = _make_activities(tokens_used=1500)
    budget_session_id = str(uuid4())
    workflow_input = WorkflowInput(
        task_id=str(uuid4()),
        prompt="Budget recovery workflow",
        agent_type="finance",
        requester_id="budget-user",
        budget_session_id=budget_session_id,
        budget_limit_usd="10.00",
        cost_per_token_usd="0.000002",
    )

    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=_TASK_QUEUE,
            workflows=[AgentTaskWorkflow],
            activities=[
                activities.pre_pii_scrub,
                activities.policy_eval,
                activities.budget_pre_check,
                activities.jit_token_issue,
                activities.llm_invoke,
                activities.budget_record_spend,
                activities.post_sanitize,
            ],
        ):
            result: WorkflowOutput = await env.client.execute_workflow(
                AgentTaskWorkflow.run,
                workflow_input,
                id=workflow_input.task_id,
                task_queue=_TASK_QUEUE,
            )

    assert result.workflow_status == "completed"
    assert result.content == "budget-ok"
    assert result.budget_spent_usd == str(Decimal("1500") * Decimal("0.000002"))


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("kill_after_stage", _GOVERNANCE_STAGE_NAMES)
async def test_budget_recovery_across_kill_at_each_stage(kill_after_stage: str) -> None:
    """W2-1 regression: exact budget spend must survive worker kill/restart at each stage."""
    expected_spend = str(Decimal("1500") * Decimal("0.000002"))

    with _MP_CONTEXT.Manager() as mgr:
        async with await WorkflowEnvironment.start_time_skipping() as env:
            target_host = _get_temporal_target_host(env)

            proc1, counts1, ready1, events1 = _start_budget_worker_process(
                target_host=target_host,
                die_after_stage=kill_after_stage,
                manager=mgr,
            )
            assert ready1.wait(timeout=15), "Budget worker 1 did not become ready in time"

            workflow_input = WorkflowInput(
                task_id=str(uuid4()),
                prompt="Budget chaos workflow",
                agent_type="finance",
                requester_id="budget-chaos-user",
                budget_session_id=str(uuid4()),
                budget_limit_usd="10.00",
                cost_per_token_usd="0.000002",
            )
            workflow_handle = await env.client.start_workflow(
                AgentTaskWorkflow.run,
                workflow_input,
                id=f"budget-chaos-{kill_after_stage}-{uuid4()}",
                task_queue=_TASK_QUEUE,
            )

            assert events1[kill_after_stage].wait(timeout=30), (
                f"Stage {kill_after_stage} did not complete before worker kill"
            )
            proc1.join(timeout=2)
            if proc1.is_alive():
                proc1.kill()
                proc1.join(timeout=2)

            proc2, counts2, ready2, _events2 = _start_budget_worker_process(
                target_host=target_host,
                die_after_stage=None,
                manager=mgr,
            )
            assert ready2.wait(timeout=15), "Budget worker 2 did not become ready in time"

            result: WorkflowOutput = await asyncio.wait_for(
                workflow_handle.result(),
                timeout=_RECOVERY_TIMEOUT_SECONDS,
            )
            proc2.kill()
            proc2.join(timeout=2)

        total_budget_record_calls = counts1.get("BudgetRecordSpend", 0) + counts2.get(
            "BudgetRecordSpend", 0
        )

    assert result.workflow_status == "completed"
    assert result.content == "budget-chaos-ok"
    assert result.budget_spent_usd == expected_spend
    assert result.tokens_used == 1500
    assert total_budget_record_calls <= 1, (
        f"BudgetRecordSpend executed {total_budget_record_calls} times across recovery; "
        "exact spend recovery must not depend on duplicate spend application"
    )
