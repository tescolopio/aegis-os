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

"""Task approval service for signaling Temporal workflows in PendingApproval."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

from src.control_plane.scheduler import (
    AgentTaskWorkflow,
    ApprovalSignalPayload,
    ApprovalStatusSnapshot,
    PendingApprovalState,
)


class PendingApprovalNotFoundError(LookupError):
    """Raised when no active pending-approval workflow exists for a task."""


@dataclass(frozen=True)
class PendingApprovalConflictError(RuntimeError):
    """Raised when a task exists but is no longer awaiting approval."""

    task_id: UUID
    approval_state: str
    workflow_status: str

    def __str__(self) -> str:
        return (
            f"Task {self.task_id} is no longer awaiting approval "
            f"(approval_state={self.approval_state}, workflow_status={self.workflow_status})"
        )


@dataclass(frozen=True)
class ApprovalDecisionResult:
    """Response returned after a workflow signal is accepted."""

    task_id: UUID
    status: str
    actor_id: str
    reason: str


class TaskApprovalService:
    """Signal approve/deny decisions to a running Temporal workflow by task ID."""

    def __init__(self, temporal_client: Any) -> None:
        self._client = temporal_client

    async def get_snapshot(self, task_id: UUID) -> ApprovalStatusSnapshot:
        """Return the approval snapshot for a task, regardless of approval state."""
        handle = self._client.get_workflow_handle(str(task_id))
        try:
            snapshot = await handle.query(AgentTaskWorkflow.approval_status)
        except Exception as exc:  # noqa: BLE001
            raise PendingApprovalNotFoundError(
                f"No active PendingApproval workflow found for task_id={task_id}"
            ) from exc

        return cast(ApprovalStatusSnapshot, snapshot)

    async def get_pending_snapshot(self, task_id: UUID) -> ApprovalStatusSnapshot:
        """Return the approval snapshot for a task currently waiting for review."""
        snapshot = await self.get_snapshot(task_id)

        if snapshot.approval_state != PendingApprovalState.AWAITING_APPROVAL.value:
            raise PendingApprovalConflictError(
                task_id=task_id,
                approval_state=snapshot.approval_state,
                workflow_status=snapshot.workflow_status,
            )
        return snapshot

    async def list_pending_snapshots(self, *, limit: int = 200) -> list[ApprovalStatusSnapshot]:
        """Return currently pending approval snapshots from open Temporal workflows."""
        snapshots: list[ApprovalStatusSnapshot] = []

        async for execution in self._client.list_workflows(limit=limit):
            if execution.close_time is not None:
                continue

            handle = self._client.get_workflow_handle(execution.id)
            try:
                snapshot = await handle.query(AgentTaskWorkflow.approval_status)
            except Exception:  # noqa: BLE001
                continue

            snapshot = cast(ApprovalStatusSnapshot, snapshot)
            if snapshot.approval_state == PendingApprovalState.AWAITING_APPROVAL.value:
                snapshots.append(snapshot)

        return snapshots

    async def approve(self, task_id: UUID, approver_id: str, reason: str) -> ApprovalDecisionResult:
        """Signal approval to a pending workflow and return the accepted decision."""
        await self.get_pending_snapshot(task_id)
        handle = self._client.get_workflow_handle(str(task_id))
        await handle.signal(
            AgentTaskWorkflow.approve,
            ApprovalSignalPayload(approver_id=approver_id, reason=reason, approved=True),
        )
        return ApprovalDecisionResult(
            task_id=task_id,
            status=PendingApprovalState.APPROVED.value,
            actor_id=approver_id,
            reason=reason,
        )

    async def deny(self, task_id: UUID, approver_id: str, reason: str) -> ApprovalDecisionResult:
        """Signal denial to a pending workflow and return the accepted decision."""
        await self.get_pending_snapshot(task_id)
        handle = self._client.get_workflow_handle(str(task_id))
        await handle.signal(
            AgentTaskWorkflow.deny,
            ApprovalSignalPayload(approver_id=approver_id, reason=reason, approved=False),
        )
        return ApprovalDecisionResult(
            task_id=task_id,
            status=PendingApprovalState.DENIED.value,
            actor_id=approver_id,
            reason=reason,
        )
