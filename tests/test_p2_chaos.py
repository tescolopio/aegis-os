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

"""Phase 2 (P2-4) chaos tests: worker kill and Temporal resumption.

These tests verify that Temporal's durable execution guarantees hold when a
worker process is killed mid-workflow.  Each test:

1. Starts a Temporal dev server via ``WorkflowEnvironment.start_time_skipping()``.
2. Starts a worker in a subprocess (``multiprocessing.Process``) with activities
   that signal a shared ``multiprocessing.Event`` when a specific stage completes.
3. Kills the worker subprocess (``Process.kill()``) immediately after the target
   stage event is set.
4. Starts a second fresh worker subprocess.
5. Asserts that the workflow resumes from the correct stage with no re-execution
   of completed stages.
6. Asserts identity preservation, no duplicate LLM calls, audit continuity, and
   recovery within 10 seconds.

All tests are marked ``@pytest.mark.integration`` and require the Temporal dev
server binary (downloaded automatically on first run and cached by the SDK).
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import threading
import time
import uuid
from typing import Any, cast

import pytest
from temporalio import activity
from temporalio.client import Client
from temporalio.service import RPCError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.adapters.base import LLMRequest, LLMResponse
from src.control_plane.scheduler import (
    AgentTaskWorkflow,
    ApprovalStatusSnapshot,
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TASK_QUEUE = "aegis-chaos-test"
_RECOVERY_TIMEOUT_SECONDS = 10.0
_STAGE_NAMES = ["PrePIIScrub", "PolicyEval", "JITTokenIssue", "LLMInvoke", "PostSanitize"]
_MP_CONTEXT = multiprocessing.get_context("spawn")


# ---------------------------------------------------------------------------
# Shared worker state helpers
# ---------------------------------------------------------------------------


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


async def _query_approval_status_with_retry(
    handle: Any,
    *,
    attempts: int = 20,
    delay_seconds: float = 0.25,
) -> ApprovalStatusSnapshot:
    """Retry workflow queries while the restarted workflow is replaying state."""
    last_error: RPCError | None = None
    for _ in range(attempts):
        try:
            snapshot = await handle.query(AgentTaskWorkflow.approval_status)
            return cast(ApprovalStatusSnapshot, snapshot)
        except RPCError as exc:
            last_error = exc
            await asyncio.sleep(delay_seconds)
    if last_error is not None:
        raise last_error
    raise RuntimeError("approval status query did not return a snapshot")


def _make_stub_adapter() -> Any:
    """Return a minimal LLM adapter that always returns a fixed response."""
    from unittest.mock import AsyncMock, MagicMock

    adapter = MagicMock()
    adapter.complete = AsyncMock(
        return_value=LLMResponse(
            content="Chaos test response",
            tokens_used=10,
            model="gpt-4o-mini",
            provider="openai",
            finish_reason="stop",
        )
    )
    return adapter


def _run_worker(
    target_host: str,
    die_after_stage: str | None,
    completion_counts: dict[str, Any],
    ready_event: Any,
    stage_done_events: dict[str, Any],
    audit_events: Any,
) -> None:
    """Worker subprocess entry point.

    Runs a Temporal worker with activities instrumented to signal ``stage_done_events``
    when each stage completes.  When ``die_after_stage`` is set, the worker calls
    a short delayed ``os._exit(1)`` after that stage's event is set to simulate
    a post-completion worker crash without dropping the activity completion.
    """

    async def _main() -> None:
        client = await Client.connect(target_host)
        adapter = _make_stub_adapter()

        @activity.defn(name="PrePIIScrub")
        async def _pre_pii_scrub(inp: WorkflowInput) -> PrePIIScrubResult:
            result = PrePIIScrubResult(sanitized_prompt=inp.prompt, pii_types=[])
            completion_counts["PrePIIScrub"] = completion_counts.get("PrePIIScrub", 0) + 1
            audit_events.append("guardrails.pre_sanitize@pre-pii-scrub")
            stage_done_events["PrePIIScrub"].set()
            if die_after_stage == "PrePIIScrub":
                _schedule_worker_exit()
            return result

        @activity.defn(name="PolicyEval")
        async def _policy_eval(inp: PolicyEvalInput) -> PolicyEvalResult:
            result = PolicyEvalResult(
                allowed=True,
                action="allow",
                fields=[],
                sanitized_prompt=inp.sanitized_prompt,
                extra_pii_types=[],
            )
            completion_counts["PolicyEval"] = completion_counts.get("PolicyEval", 0) + 1
            audit_events.append("policy.allowed@policy-eval")
            stage_done_events["PolicyEval"].set()
            if die_after_stage == "PolicyEval":
                _schedule_worker_exit()
            return result

        @activity.defn(name="JITTokenIssue")
        async def _jit_token_issue(inp: JITTokenInput) -> JITTokenResult:
            from src.governance.session_mgr import SessionManager

            session_mgr = SessionManager()
            token = session_mgr.issue_token(
                agent_type=inp.agent_type, requester_id=inp.requester_id
            )
            claims = session_mgr.validate_token(token)
            result = JITTokenResult(token=token, jti=claims.jti)
            completion_counts["JITTokenIssue"] = completion_counts.get("JITTokenIssue", 0) + 1
            audit_events.append("token.issued@jit-token-issue")
            stage_done_events["JITTokenIssue"].set()
            if die_after_stage == "JITTokenIssue":
                _schedule_worker_exit()
            return result

        @activity.defn(name="LLMInvoke")
        async def _llm_invoke(inp: LLMInvokeInput) -> LLMInvokeResult:
            llm_req = LLMRequest(
                prompt=inp.sanitized_prompt,
                model=inp.model,
                max_tokens=inp.max_tokens,
                temperature=inp.temperature,
                system_prompt=inp.system_prompt,
                metadata={"aegis_token": inp.token},
            )
            response = await adapter.complete(llm_req)
            result = LLMInvokeResult(
                content=response.content,
                tokens_used=response.tokens_used,
                model=response.model,
                provider=response.provider,
            )
            completion_counts["LLMInvoke"] = completion_counts.get("LLMInvoke", 0) + 1
            audit_events.append("llm.completed@llm-invoke")
            stage_done_events["LLMInvoke"].set()
            if die_after_stage == "LLMInvoke":
                _schedule_worker_exit()
            return result

        @activity.defn(name="PostSanitize")
        async def _post_sanitize(inp: PostSanitizeInput) -> PostSanitizeResult:
            result = PostSanitizeResult(sanitized_content=inp.content, pii_types=[])
            completion_counts["PostSanitize"] = completion_counts.get("PostSanitize", 0) + 1
            audit_events.append("guardrails.post_sanitize@post-sanitize")
            stage_done_events["PostSanitize"].set()
            if die_after_stage == "PostSanitize":
                _schedule_worker_exit()
            return result

        ready_event.set()  # Signal that worker is registered and running.
        async with Worker(
            client,
            task_queue=_TASK_QUEUE,
            workflows=[AgentTaskWorkflow],
            activities=[
                _pre_pii_scrub,
                _policy_eval,
                _jit_token_issue,
                _llm_invoke,
                _post_sanitize,
            ],
        ):
            # Run until killed or stage event fires (kill handled by os._exit).
            await asyncio.sleep(60)

    asyncio.run(_main())


def _start_worker_process(
    target_host: str,
    die_after_stage: str | None,
    manager: multiprocessing.managers.SyncManager,
) -> tuple[Any, Any, Any, Any, Any]:
    """Start a worker subprocess and return the process plus shared state objects."""
    completion_counts: Any = manager.dict()
    ready_event = manager.Event()
    stage_done_events: dict[str, Any] = {
        name: manager.Event() for name in _STAGE_NAMES
    }
    audit_events = manager.list()

    proc = _MP_CONTEXT.Process(
        target=_run_worker,
        args=(
            target_host,
            die_after_stage,
            completion_counts,
            ready_event,
            stage_done_events,
            audit_events,
        ),
        daemon=True,
    )
    proc.start()
    return proc, completion_counts, ready_event, stage_done_events, audit_events


# ---------------------------------------------------------------------------
# Chaos test cases
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestWorkerKillResumption:
    """P2-4 chaos: worker killed after each stage; verify Temporal resumes correctly."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("kill_after_stage", _STAGE_NAMES)
    async def test_kill_at_each_stage_workflow_completes(
        self, kill_after_stage: str
    ) -> None:
        """Kill worker after ``kill_after_stage``; verify workflow eventually completes.

        Steps:
        1. Submit ``AgentTaskWorkflow``.
        2. Worker 1: runs activities, kills itself after ``kill_after_stage``.
        3. Worker 2: started fresh; Temporal dispatches remaining activities.
        4. Assert final status is ``completed`` within ``_RECOVERY_TIMEOUT_SECONDS``.
        """
        with _MP_CONTEXT.Manager() as mgr:
            async with await WorkflowEnvironment.start_time_skipping() as env:
                target_host = _get_temporal_target_host(env)

                # Start Worker 1 — will die after kill_after_stage.
                proc1, counts1, ready1, events1, _audit1 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage=kill_after_stage,
                    manager=mgr,
                )

                # Wait for Worker 1 to be ready.
                assert ready1.wait(timeout=15), "Worker 1 did not become ready in time"

                # Submit the workflow.
                inp = WorkflowInput(
                    task_id=str(uuid.uuid4()),
                    prompt="Chaos test prompt",
                    agent_type="general",
                    requester_id="chaos-user",
                )
                wf_handle = await env.client.start_workflow(
                    AgentTaskWorkflow.run,
                    inp,
                    id=f"chaos-{kill_after_stage}-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )
                original_task_id = inp.task_id

                # Wait for kill_after_stage to complete, then Worker 1 dies.
                killed_event = events1[kill_after_stage]
                assert killed_event.wait(timeout=30), (
                    f"Stage {kill_after_stage} did not complete in time"
                )
                # Process kills itself after setting the event, give it a moment.
                proc1.join(timeout=2)
                if proc1.is_alive():
                    proc1.kill()
                    proc1.join(timeout=2)

                # If kill was at the last stage, workflow may already be done.
                if kill_after_stage == "PostSanitize":
                    # Workflow completes from Worker 1 before kill is observed.
                    try:
                        result: WorkflowOutput = await asyncio.wait_for(
                            wf_handle.result(),
                            timeout=_RECOVERY_TIMEOUT_SECONDS,
                        )
                        assert result.workflow_status == "completed"
                    except TimeoutError:
                        # Start Worker 2 anyway.
                        pass

                # Start Worker 2 — no kill condition.
                proc2, counts2, ready2, events2, _audit2 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage=None,
                    manager=mgr,
                )
                assert ready2.wait(timeout=15), "Worker 2 did not become ready in time"

                # Record the time Worker 2 started.
                worker2_start = time.monotonic()

                # Wait for workflow to complete.
                result = await asyncio.wait_for(
                    wf_handle.result(),
                    timeout=_RECOVERY_TIMEOUT_SECONDS,
                )

                recovery_seconds = time.monotonic() - worker2_start
                proc2.kill()
                proc2.join(timeout=2)

            # Assertions.
            assert result.workflow_status == "completed", (
                f"Expected 'completed', got {result.workflow_status!r}"
            )
            assert result.content, "Resumed workflow must return non-empty content"
            assert result.task_id == original_task_id, (
                "task_id must be preserved through kill/restart"
            )
            assert recovery_seconds < _RECOVERY_TIMEOUT_SECONDS, (
                f"Recovery took {recovery_seconds:.1f}s, must be < {_RECOVERY_TIMEOUT_SECONDS}s"
            )

    @pytest.mark.asyncio
    async def test_no_duplicate_llm_calls_across_kill_restart(self) -> None:
        """LLMInvoke must be executed at most once regardless of worker restarts."""
        with _MP_CONTEXT.Manager() as mgr:
            async with await WorkflowEnvironment.start_time_skipping() as env:
                target_host = _get_temporal_target_host(env)

                # Kill worker after PolicyEval (before LLMInvoke).
                proc1, counts1, ready1, events1, _audit1 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage="PolicyEval",
                    manager=mgr,
                )
                assert ready1.wait(timeout=15)

                inp = WorkflowInput(
                    task_id=str(uuid.uuid4()),
                    prompt="No duplicate LLM",
                    agent_type="general",
                    requester_id="chaos-no-dup",
                )
                wf_handle = await env.client.start_workflow(
                    AgentTaskWorkflow.run,
                    inp,
                    id=f"no-dup-llm-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

                # Wait for PolicyEval, then kill.
                assert events1["PolicyEval"].wait(timeout=30)
                proc1.join(timeout=2)
                if proc1.is_alive():
                    proc1.kill()
                    proc1.join(timeout=2)

                # Start Worker 2.
                proc2, counts2, ready2, events2, _audit2 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage=None,
                    manager=mgr,
                )
                assert ready2.wait(timeout=15)

                await asyncio.wait_for(wf_handle.result(), timeout=30.0)
                proc2.kill()
                proc2.join(timeout=2)

            # Combine counts from both workers.
            llm_count_w1 = counts1.get("LLMInvoke", 0)
            llm_count_w2 = counts2.get("LLMInvoke", 0)
            total_llm_calls = llm_count_w1 + llm_count_w2

            assert total_llm_calls <= 1, (
                f"LLMInvoke called {total_llm_calls} times across kill/restart; "
                "must be at most 1 (no duplicate LLM calls)"
            )

    @pytest.mark.asyncio
    async def test_identity_preserved_across_restart(self) -> None:
        """task_id must be identical before and after worker kill/restart."""
        with _MP_CONTEXT.Manager() as mgr:
            async with await WorkflowEnvironment.start_time_skipping() as env:
                target_host = _get_temporal_target_host(env)

                proc1, counts1, ready1, events1, _audit1 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage="PrePIIScrub",
                    manager=mgr,
                )
                assert ready1.wait(timeout=15)

                original_task_id = str(uuid.uuid4())
                inp = WorkflowInput(
                    task_id=original_task_id,
                    prompt="Identity check",
                    agent_type="general",
                    requester_id="identity-user",
                    session_id="identity-session-1",
                )
                wf_handle = await env.client.start_workflow(
                    AgentTaskWorkflow.run,
                    inp,
                    id=f"identity-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

                assert events1["PrePIIScrub"].wait(timeout=30)
                proc1.join(timeout=2)
                if proc1.is_alive():
                    proc1.kill()
                    proc1.join(timeout=2)

                proc2, counts2, ready2, events2, _audit2 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage=None,
                    manager=mgr,
                )
                assert ready2.wait(timeout=15)

                snapshot = await _query_approval_status_with_retry(wf_handle)
                assert snapshot.task_id == original_task_id
                assert snapshot.session_id == "identity-session-1"
                assert snapshot.agent_type == "general"

                result = await asyncio.wait_for(wf_handle.result(), timeout=30.0)
                proc2.kill()
                proc2.join(timeout=2)

            assert result.task_id == original_task_id, (
                f"task_id changed after restart: original={original_task_id!r}, "
                f"result={result.task_id!r}"
            )

    @pytest.mark.asyncio
    async def test_completed_stages_not_re_executed_after_restart(self) -> None:
        """Stages completed before worker kill must not be re-executed after restart.

        Kill after PolicyEval; verify PrePIIScrub and PolicyEval run exactly once
        (total across both workers), while remaining stages run once on Worker 2.
        """
        with _MP_CONTEXT.Manager() as mgr:
            async with await WorkflowEnvironment.start_time_skipping() as env:
                target_host = _get_temporal_target_host(env)

                proc1, counts1, ready1, events1, _audit1 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage="PolicyEval",
                    manager=mgr,
                )
                assert ready1.wait(timeout=15)

                inp = WorkflowInput(
                    task_id=str(uuid.uuid4()),
                    prompt="No re-execution test",
                    agent_type="general",
                    requester_id="re-exec-user",
                )
                wf_handle = await env.client.start_workflow(
                    AgentTaskWorkflow.run,
                    inp,
                    id=f"no-reexec-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

                assert events1["PolicyEval"].wait(timeout=30)
                proc1.join(timeout=2)
                if proc1.is_alive():
                    proc1.kill()
                    proc1.join(timeout=2)

                proc2, counts2, ready2, events2, _audit2 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage=None,
                    manager=mgr,
                )
                assert ready2.wait(timeout=15)
                result = await asyncio.wait_for(wf_handle.result(), timeout=30.0)
                proc2.kill()
                proc2.join(timeout=2)

            total_pre = counts1.get("PrePIIScrub", 0) + counts2.get("PrePIIScrub", 0)
            total_policy = counts1.get("PolicyEval", 0) + counts2.get("PolicyEval", 0)
            total_llm = counts1.get("LLMInvoke", 0) + counts2.get("LLMInvoke", 0)
            total_post = counts1.get("PostSanitize", 0) + counts2.get("PostSanitize", 0)

            assert total_pre == 1, (
                f"PrePIIScrub re-executed; expected 1, got {total_pre}"
            )
            assert total_policy == 1, (
                f"PolicyEval re-executed; expected 1, got {total_policy}"
            )
            assert total_llm == 1, f"LLMInvoke not executed once; got {total_llm}"
            assert total_post == 1, f"PostSanitize not executed once; got {total_post}"
            assert result.workflow_status == "completed"

    @pytest.mark.asyncio
    async def test_recovery_within_performance_gate(self) -> None:
        """Workflow must reach 'completed' within 10 seconds of worker restart."""
        with _MP_CONTEXT.Manager() as mgr:
            async with await WorkflowEnvironment.start_time_skipping() as env:
                target_host = _get_temporal_target_host(env)

                proc1, counts1, ready1, events1, _audit1 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage="JITTokenIssue",
                    manager=mgr,
                )
                assert ready1.wait(timeout=15)

                inp = WorkflowInput(
                    task_id=str(uuid.uuid4()),
                    prompt="Performance gate test",
                    agent_type="general",
                    requester_id="perf-user",
                )
                wf_handle = await env.client.start_workflow(
                    AgentTaskWorkflow.run,
                    inp,
                    id=f"perf-gate-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )

                assert events1["JITTokenIssue"].wait(timeout=30)
                proc1.join(timeout=2)
                if proc1.is_alive():
                    proc1.kill()
                    proc1.join(timeout=2)

                # Record restart time.
                restart_time = time.monotonic()

                proc2, counts2, ready2, events2, _audit2 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage=None,
                    manager=mgr,
                )
                assert ready2.wait(timeout=15)

                result = await asyncio.wait_for(
                    wf_handle.result(),
                    timeout=_RECOVERY_TIMEOUT_SECONDS,
                )
                elapsed = time.monotonic() - restart_time
                proc2.kill()
                proc2.join(timeout=2)

            assert result.workflow_status == "completed"
            assert elapsed < _RECOVERY_TIMEOUT_SECONDS, (
                f"Recovery time {elapsed:.2f}s exceeded gate of {_RECOVERY_TIMEOUT_SECONDS}s"
            )

    @pytest.mark.asyncio
    async def test_audit_event_sequence_matches_uninterrupted_run(self) -> None:
        """Kill/restart must preserve the same stage-event ordering as an uninterrupted run."""
        with _MP_CONTEXT.Manager() as mgr:
            async with await WorkflowEnvironment.start_time_skipping() as env:
                target_host = _get_temporal_target_host(env)

                (
                    baseline_proc,
                    _baseline_counts,
                    baseline_ready,
                    _baseline_events,
                    baseline_audit,
                ) = _start_worker_process(
                    target_host=target_host,
                    die_after_stage=None,
                    manager=mgr,
                )
                assert baseline_ready.wait(timeout=15)

                baseline_input = WorkflowInput(
                    task_id=str(uuid.uuid4()),
                    prompt="Baseline audit continuity",
                    agent_type="general",
                    requester_id="audit-user",
                )
                baseline_handle = await env.client.start_workflow(
                    AgentTaskWorkflow.run,
                    baseline_input,
                    id=f"audit-baseline-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )
                baseline_result = await asyncio.wait_for(baseline_handle.result(), timeout=30.0)
                baseline_proc.kill()
                baseline_proc.join(timeout=2)

                proc1, _counts1, ready1, events1, audit1 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage="PolicyEval",
                    manager=mgr,
                )
                assert ready1.wait(timeout=15)

                resumed_input = WorkflowInput(
                    task_id=str(uuid.uuid4()),
                    prompt="Restart audit continuity",
                    agent_type="general",
                    requester_id="audit-user",
                )
                resumed_handle = await env.client.start_workflow(
                    AgentTaskWorkflow.run,
                    resumed_input,
                    id=f"audit-resume-{uuid.uuid4()}",
                    task_queue=_TASK_QUEUE,
                )
                assert events1["PolicyEval"].wait(timeout=30)
                proc1.join(timeout=2)
                if proc1.is_alive():
                    proc1.kill()
                    proc1.join(timeout=2)

                proc2, _counts2, ready2, _events2, audit2 = _start_worker_process(
                    target_host=target_host,
                    die_after_stage=None,
                    manager=mgr,
                )
                assert ready2.wait(timeout=15)
                resumed_result = await asyncio.wait_for(resumed_handle.result(), timeout=30.0)
                proc2.kill()
                proc2.join(timeout=2)

            assert baseline_result.workflow_status == "completed"
            assert resumed_result.workflow_status == "completed"
            baseline_sequence = list(baseline_audit)
            resumed_sequence = list(audit1) + list(audit2)
            assert resumed_sequence == baseline_sequence, (
                "Kill/restart audit sequence must match uninterrupted run\n"
                f"baseline={baseline_sequence}\nresumed={resumed_sequence}"
            )
