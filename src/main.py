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

"""Aegis-OS Control Plane API entry point."""

import time
from collections.abc import Callable
from typing import Protocol

from fastapi import FastAPI, Response
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from temporalio.client import Client

from src.audit_vault.logger import AuditLogger
from src.config import settings
from src.control_plane.approval_service import TaskApprovalService
from src.control_plane.data_converter import create_aegis_data_converter
from src.control_plane.router import configure_hitl_controls
from src.control_plane.router import router as control_router
from src.control_plane.scheduler import ApprovalStatusSnapshot
from src.governance.policy_engine.opa_client import PolicyEngine
from src.governance.session_mgr import SessionManager
from src.watchdog.metrics import workflow_pending_approval_seconds

# ---------------------------------------------------------------------------
# OpenTelemetry provider setup
# Must be configured before any AuditLogger or tracer is created.
# In production, replace ConsoleSpanExporter with an OTLP exporter via
# environment-variable-driven SDK auto-configuration.
# ---------------------------------------------------------------------------
_otel_provider = TracerProvider()
_otel_provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
trace.set_tracer_provider(_otel_provider)

app = FastAPI(
    title="Aegis-OS Control Plane",
    description="The Control Plane for the Enterprise Synthetic Workforce",
    version="0.1.0",
)

# Include routers
app.include_router(control_router, prefix="/api/v1")

_audit_logger = AuditLogger()
_tracked_pending_approval_workflow_ids: set[str] = set()


class PendingApprovalSnapshotSource(Protocol):
    """Minimal interface required to refresh PendingApproval Prometheus metrics."""

    async def list_pending_snapshots(self, *, limit: int = 200) -> list[ApprovalStatusSnapshot]:
        """Return the current pending approval snapshots."""


async def refresh_pending_approval_metrics(
    approval_service: PendingApprovalSnapshotSource | None,
    *,
    now_fn: Callable[[], float] | None = None,
) -> None:
    """Refresh the PendingApproval duration gauge from live Temporal workflow state."""
    global _tracked_pending_approval_workflow_ids  # noqa: PLW0603

    current_workflow_ids: set[str] = set()
    snapshots = []

    if approval_service is not None:
        try:
            snapshots = await approval_service.list_pending_snapshots()
        except Exception as exc:  # noqa: BLE001
            _audit_logger.warning("aegis.hitl_metrics_refresh_failed", error=str(exc))

    now_seconds = (now_fn or time.time)()
    for snapshot in snapshots:
        if snapshot.pending_since_epoch_seconds is None:
            continue

        age_seconds = max(now_seconds - snapshot.pending_since_epoch_seconds, 0.0)
        workflow_pending_approval_seconds.labels(workflow_id=snapshot.task_id).set(age_seconds)
        current_workflow_ids.add(snapshot.task_id)

    stale_workflow_ids = _tracked_pending_approval_workflow_ids - current_workflow_ids
    for workflow_id in stale_workflow_ids:
        workflow_pending_approval_seconds.remove(workflow_id)

    _tracked_pending_approval_workflow_ids = current_workflow_ids


async def _connect_temporal_client() -> Client:
    """Create the Temporal client used by live HITL approval endpoints."""
    return await Client.connect(
        settings.temporal_host,
        data_converter=create_aegis_data_converter(),
    )


@app.on_event("startup")
async def startup_event() -> None:
    _audit_logger.info("aegis.startup", message="Aegis-OS Control Plane starting up")
    temporal_client = await _connect_temporal_client()
    app.state.temporal_client = temporal_client
    app.state.hitl_policy_engine = PolicyEngine()
    app.state.hitl_session_mgr = SessionManager()
    app.state.hitl_approval_service = TaskApprovalService(temporal_client)
    configure_hitl_controls(
        approval_service=app.state.hitl_approval_service,
        policy_engine=app.state.hitl_policy_engine,
        session_mgr=app.state.hitl_session_mgr,
    )
    _audit_logger.info(
        "aegis.hitl_controls_configured",
        temporal_host=settings.temporal_host,
    )


@app.on_event("shutdown")
async def shutdown_event() -> None:
    temporal_client = getattr(app.state, "temporal_client", None)
    if temporal_client is not None and hasattr(temporal_client, "close"):
        maybe_close = temporal_client.close
        if callable(maybe_close):
            result = maybe_close()
            if hasattr(result, "__await__"):
                await result
    _audit_logger.info("aegis.shutdown", message="Aegis-OS Control Plane shutting down")


@app.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    """Expose Prometheus metrics after refreshing live PendingApproval gauges."""
    approval_service = getattr(app.state, "hitl_approval_service", None)
    await refresh_pending_approval_metrics(approval_service)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "aegis-os"}
