"""W2-2 Temporal integration tests for durable loop-detector state."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import re
import threading
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, cast
from uuid import uuid4

import pytest
from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.audit_vault.logger import AuditLogger
from src.control_plane.scheduler import (
    AegisActivities,
    LoopRecordInput,
    LoopRecordResult,
)
from src.watchdog.loop_detector import LoopSignal

_STEP_COUNT_RE = re.compile(r"step_count=(\d+)")
_TOTAL_TOKENS_RE = re.compile(r"total_tokens=(\d+)")

_TASK_QUEUE = "aegis-loop-recovery"
_RECOVERY_TIMEOUT_SECONDS = 10.0
_MP_CONTEXT = multiprocessing.get_context("spawn")


@dataclass
class LoopRecoveryInput:
    """Input for the loop-recovery test workflow."""

    task_id: str
    loop_session_id: str
    agent_type: str
    signals: list[LoopSignal]
    token_deltas: list[int]
    max_agent_steps: int
    max_token_velocity: int = 1_000


@dataclass
class LoopRecoveryOutput:
    """Result for the loop-recovery test workflow."""

    status: str
    step_count: int
    total_tokens: int
    error_type: str | None = None


@workflow.defn(name="LoopRecoveryWorkflow", sandboxed=False)
class LoopRecoveryWorkflow:
    """Workflow that exercises LoopRecordStep across multiple durable steps."""

    @workflow.run
    async def run(self, inp: LoopRecoveryInput) -> LoopRecoveryOutput:
        checkpoint = None
        last_result: LoopRecordResult | None = None
        for index, signal in enumerate(inp.signals, start=1):
            try:
                last_result = await workflow.execute_activity(
                    "LoopRecordStep",
                    LoopRecordInput(
                        task_id=inp.task_id,
                        agent_type=inp.agent_type,
                        loop_session_id=inp.loop_session_id,
                        token_delta=inp.token_deltas[index - 1],
                        signal=signal,
                        description=f"step-{index}",
                        checkpoint=checkpoint,
                        max_agent_steps=inp.max_agent_steps,
                        max_token_velocity=inp.max_token_velocity,
                    ),
                    result_type=LoopRecordResult,
                    schedule_to_close_timeout=timedelta(minutes=5),
                    retry_policy=RetryPolicy(
                        maximum_attempts=1,
                        non_retryable_error_types=[
                            "LoopDetectedError",
                            "TokenVelocityError",
                            "PendingApprovalError",
                        ],
                    ),
                )
            except ActivityError as exc:
                cause = exc.cause
                if isinstance(cause, ApplicationError):
                    message = cause.message or ""
                    step_match = _STEP_COUNT_RE.search(message)
                    total_match = _TOTAL_TOKENS_RE.search(message)
                    step_count = (
                        int(step_match.group(1))
                        if step_match is not None
                        else (last_result.step_count if last_result is not None else index)
                    )
                    total_tokens = (
                        int(total_match.group(1))
                        if total_match is not None
                        else last_result.total_tokens
                        if last_result is not None
                        else sum(inp.token_deltas[:index])
                    )
                    return LoopRecoveryOutput(
                        status="halted",
                        step_count=step_count,
                        total_tokens=total_tokens,
                        error_type=cause.type,
                    )
                raise
            checkpoint = last_result.checkpoint
        assert last_result is not None
        return LoopRecoveryOutput(
            status="completed",
            step_count=last_result.step_count,
            total_tokens=last_result.total_tokens,
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


def _run_loop_worker(
    target_host: str,
    die_after_step: str | None,
    ready_event: Any,
    step_events: dict[str, Any],
) -> None:
    """Run a subprocess worker that executes loop-recovery activities."""

    async def _main() -> None:
        client = await Client.connect(target_host)
        activities = AegisActivities(
            adapter=cast(Any, object()),
            audit_logger=AuditLogger("loop-recovery-worker"),
        )

        @activity.defn(name="LoopRecordStep")
        async def _loop_record_step(inp: LoopRecordInput) -> LoopRecordResult:
            result = await activities.loop_record_step(inp)
            step_events[inp.description].set()
            if die_after_step == inp.description:
                _schedule_worker_exit()
            return result

        ready_event.set()
        async with Worker(
            client,
            task_queue=_TASK_QUEUE,
            workflows=[LoopRecoveryWorkflow],
            activities=[_loop_record_step],
        ):
            await asyncio.sleep(60)

    asyncio.run(_main())


def _start_loop_worker_process(
    target_host: str,
    die_after_step: str | None,
    manager: multiprocessing.managers.SyncManager,
) -> tuple[Any, Any, Any]:
    """Start a loop-recovery worker subprocess and return shared state handles."""
    ready_event = manager.Event()
    step_events = {f"step-{index}": manager.Event() for index in range(1, 6)}
    proc = _MP_CONTEXT.Process(
        target=_run_loop_worker,
        args=(target_host, die_after_step, ready_event, step_events),
        daemon=True,
    )
    proc.start()
    return proc, ready_event, step_events


@pytest.mark.integration
@pytest.mark.asyncio
async def test_loop_counter_survives_temporal_restart_and_halts_on_cumulative_step() -> None:
    """W2-2: a restart must preserve the NO_PROGRESS streak and halt at the correct step."""
    with _MP_CONTEXT.Manager() as mgr:
        async with await WorkflowEnvironment.start_time_skipping() as env:
            target_host = _get_temporal_target_host(env)
            proc1, ready1, step_events1 = _start_loop_worker_process(
                target_host=target_host,
                die_after_step="step-3",
                manager=mgr,
            )
            assert ready1.wait(timeout=15)

            workflow_input = LoopRecoveryInput(
                task_id=str(uuid4()),
                loop_session_id=str(uuid4()),
                agent_type="finance",
                signals=[
                    LoopSignal.NO_PROGRESS,
                    LoopSignal.NO_PROGRESS,
                    LoopSignal.NO_PROGRESS,
                    LoopSignal.NO_PROGRESS,
                ],
                token_deltas=[10, 10, 10, 10],
                max_agent_steps=4,
            )
            handle = await env.client.start_workflow(
                LoopRecoveryWorkflow.run,
                workflow_input,
                id=f"loop-recovery-{uuid4()}",
                task_queue=_TASK_QUEUE,
            )

            assert step_events1["step-3"].wait(timeout=30)
            proc1.join(timeout=2)
            if proc1.is_alive():
                proc1.kill()
                proc1.join(timeout=2)

            proc2, ready2, _step_events2 = _start_loop_worker_process(
                target_host=target_host,
                die_after_step=None,
                manager=mgr,
            )
            assert ready2.wait(timeout=15)

            result = await asyncio.wait_for(handle.result(), timeout=_RECOVERY_TIMEOUT_SECONDS)
            proc2.kill()
            proc2.join(timeout=2)

    assert result.status == "halted"
    assert result.error_type == "LoopDetectedError"
    assert result.step_count == 4
    assert result.total_tokens == 40


@pytest.mark.integration
@pytest.mark.asyncio
async def test_loop_progress_reset_survives_temporal_restart_without_false_trip() -> None:
    """W2-2: a PROGRESS reset must survive restart so later NO_PROGRESS steps do not false-trip."""
    with _MP_CONTEXT.Manager() as mgr:
        async with await WorkflowEnvironment.start_time_skipping() as env:
            target_host = _get_temporal_target_host(env)
            proc1, ready1, step_events1 = _start_loop_worker_process(
                target_host=target_host,
                die_after_step="step-3",
                manager=mgr,
            )
            assert ready1.wait(timeout=15)

            workflow_input = LoopRecoveryInput(
                task_id=str(uuid4()),
                loop_session_id=str(uuid4()),
                agent_type="finance",
                signals=[
                    LoopSignal.NO_PROGRESS,
                    LoopSignal.NO_PROGRESS,
                    LoopSignal.PROGRESS,
                    LoopSignal.NO_PROGRESS,
                    LoopSignal.NO_PROGRESS,
                ],
                token_deltas=[10, 10, 5, 5, 5],
                max_agent_steps=3,
            )
            handle = await env.client.start_workflow(
                LoopRecoveryWorkflow.run,
                workflow_input,
                id=f"loop-progress-reset-{uuid4()}",
                task_queue=_TASK_QUEUE,
            )

            assert step_events1["step-3"].wait(timeout=30)
            proc1.join(timeout=2)
            if proc1.is_alive():
                proc1.kill()
                proc1.join(timeout=2)

            proc2, ready2, _step_events2 = _start_loop_worker_process(
                target_host=target_host,
                die_after_step=None,
                manager=mgr,
            )
            assert ready2.wait(timeout=15)

            result = await asyncio.wait_for(handle.result(), timeout=_RECOVERY_TIMEOUT_SECONDS)
            proc2.kill()
            proc2.join(timeout=2)

    assert result.status == "completed"
    assert result.error_type is None
    assert result.step_count == 5
    assert result.total_tokens == 35
