#!/usr/bin/env python3
"""Verify the PendingApproval demo flow against a live dev stack.

This script is intended for local demos after bringing up the Docker Compose
stack. It starts a real Temporal workflow that enters ``PendingApproval``,
waits until the API's Prometheus endpoint exposes
``aegis_workflow_pending_approval_seconds`` for that workflow, sends an admin
approve/deny decision through the REST API, and then confirms the metric is
cleared.

The default action is ``deny`` so the workflow can complete without invoking a
live LLM provider.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from typing import Any, cast
from uuid import uuid4

import httpx
from temporalio.client import Client

from src.config import settings
from src.control_plane.data_converter import create_aegis_data_converter
from src.control_plane.scheduler import (
    AgentTaskWorkflow,
    ApprovalStatusSnapshot,
    PendingApprovalState,
    WorkflowInput,
)
from src.governance.session_mgr import SessionManager

_METRIC_NAME = "aegis_workflow_pending_approval_seconds"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify the live PendingApproval demo flow against the dev stack.",
    )
    parser.add_argument(
        "--api-base-url",
        default="http://localhost:18000",
        help="Base URL of the Aegis API service.",
    )
    parser.add_argument(
        "--temporal-host",
        default=settings.temporal_host,
        help="Temporal target host used by the worker and API.",
    )
    parser.add_argument(
        "--task-queue",
        default=settings.temporal_task_queue,
        help="Temporal task queue hosting AgentTaskWorkflow workers.",
    )
    parser.add_argument(
        "--action",
        choices=("approve", "deny"),
        default="deny",
        help="HITL action to send after the metric appears. Defaults to deny to avoid LLM usage.",
    )
    parser.add_argument(
        "--approver-id",
        default="admin-user",
        help="Admin principal used in the HITL decision request.",
    )
    parser.add_argument(
        "--reason",
        default="Demo verification completed.",
        help="Reason recorded in the approve/deny request.",
    )
    parser.add_argument(
        "--requester-id",
        default="demo-operator",
        help="Requester ID stamped onto the demo workflow input.",
    )
    parser.add_argument(
        "--projected-spend-usd",
        default="75.25",
        help="Projected spend used to force the workflow into PendingApproval.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="Timeout for waiting on workflow state and metrics.",
    )
    return parser


async def _wait_for_pending_state(handle: Any, timeout_seconds: float) -> ApprovalStatusSnapshot:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        snapshot = cast(
            ApprovalStatusSnapshot,
            await handle.query(AgentTaskWorkflow.approval_status),
        )
        if snapshot.approval_state == PendingApprovalState.AWAITING_APPROVAL.value:
            return snapshot
        await asyncio.sleep(0.5)
    raise TimeoutError("Workflow did not reach PendingApproval before timeout")


async def _wait_for_metric(
    api_base_url: str,
    task_id: str,
    *,
    should_exist: bool,
    timeout_seconds: float,
) -> str:
    metric_pattern = re.compile(
        rf'^{_METRIC_NAME}\{{workflow_id="{re.escape(task_id)}"\}}\s+([0-9.]+)$',
        re.MULTILINE,
    )
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    async with httpx.AsyncClient(timeout=5.0) as client:
        while asyncio.get_running_loop().time() < deadline:
            response = await client.get(f"{api_base_url}/metrics")
            response.raise_for_status()
            text = response.text
            matched = metric_pattern.search(text)
            if should_exist and matched is not None:
                return matched.group(0)
            if not should_exist and matched is None:
                return text
            await asyncio.sleep(1.0)
    state = "appear" if should_exist else "clear"
    raise TimeoutError(f"PendingApproval metric did not {state} before timeout")


def _issue_admin_token(*, session_id: str, requester_id: str) -> str:
    session_mgr = SessionManager()
    return session_mgr.issue_token(
        agent_type="general",
        requester_id=requester_id,
        session_id=session_id,
        allowed_actions=["hitl:approve", "hitl:deny"],
        role="admin",
    )


async def _send_decision(
    *,
    api_base_url: str,
    task_id: str,
    action: str,
    approver_id: str,
    reason: str,
    session_id: str,
) -> dict[str, Any]:
    token = _issue_admin_token(session_id=session_id, requester_id=approver_id)
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{api_base_url}/api/v1/tasks/{task_id}/{action}",
            json={"approver_id": approver_id, "reason": reason},
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        return cast(dict[str, Any], response.json())


async def _run(args: argparse.Namespace) -> int:
    task_id = str(uuid4())
    session_id = f"demo-session-{task_id}"
    workflow_input = WorkflowInput(
        task_id=task_id,
        prompt="Demo PendingApproval verification request.",
        agent_type="general",
        requester_id=args.requester_id,
        session_id=session_id,
        projected_spend_usd=args.projected_spend_usd,
        approval_timeout_seconds=max(int(args.timeout_seconds), 5),
    )

    client = await Client.connect(
        args.temporal_host,
        data_converter=create_aegis_data_converter(),
    )
    handle = await client.start_workflow(
        AgentTaskWorkflow.run,
        workflow_input,
        id=workflow_input.task_id,
        task_queue=args.task_queue,
    )

    snapshot = await _wait_for_pending_state(handle, args.timeout_seconds)
    print(f"workflow.pending task_id={task_id} session_id={session_id}")

    metric_line = await _wait_for_metric(
        args.api_base_url,
        task_id,
        should_exist=True,
        timeout_seconds=args.timeout_seconds,
    )
    print(f"metrics.visible {metric_line}")

    decision_payload = await _send_decision(
        api_base_url=args.api_base_url,
        task_id=task_id,
        action=args.action,
        approver_id=args.approver_id,
        reason=args.reason,
        session_id=snapshot.session_id or session_id,
    )
    print(f"api.{args.action} {json.dumps(decision_payload, sort_keys=True)}")

    await _wait_for_metric(
        args.api_base_url,
        task_id,
        should_exist=False,
        timeout_seconds=args.timeout_seconds,
    )
    print(f"metrics.cleared task_id={task_id}")

    if args.action == "deny":
        result = await handle.result()
        print(
            "workflow.completed "
            f"status={result.workflow_status} approval_state={result.approval_state}"
        )
    else:
        print(
            "workflow.approve.sent action=approve "
            "note=approved workflows continue to the LLM stage and may require a live provider"
        )

    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
