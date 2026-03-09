# Copyright 2026 Tim Escolopio / 3D Tech Solutions
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Temporal worker entrypoint for Phase 2 durable workflows."""

from __future__ import annotations

import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from src.adapters.anthropic_adapter import AnthropicAdapter
from src.adapters.base import BaseAdapter
from src.adapters.local_llama import LocalLlamaAdapter
from src.adapters.openai_adapter import OpenAIAdapter
from src.audit_vault.logger import AuditLogger
from src.config import settings
from src.control_plane.data_converter import create_aegis_data_converter
from src.control_plane.scheduler import AegisActivities, AgentTaskWorkflow, WorkflowAuditActivities
from src.governance.policy_engine import PolicyEngine
from src.governance.session_mgr import SessionManager
from src.watchdog.budget_enforcer import BudgetEnforcer
from src.watchdog.loop_detector import LoopDetector


def build_adapter(
    *,
    session_mgr: SessionManager | None = None,
    audit_logger: AuditLogger | None = None,
) -> BaseAdapter:
    """Build the configured adapter used by the Temporal worker."""
    session_manager = session_mgr if session_mgr is not None else SessionManager()
    logger = audit_logger if audit_logger is not None else AuditLogger("temporal-worker")

    if settings.llm_provider == "openai":
        if not settings.openai_api_key:
            raise RuntimeError("AEGIS_OPENAI_API_KEY is required when AEGIS_LLM_PROVIDER=openai")
        return OpenAIAdapter(
            api_key=settings.openai_api_key,
            session_mgr=session_manager,
            audit_logger=logger,
        )

    if settings.llm_provider == "anthropic":
        if not settings.anthropic_api_key:
            raise RuntimeError(
                "AEGIS_ANTHROPIC_API_KEY is required when AEGIS_LLM_PROVIDER=anthropic"
            )
        return AnthropicAdapter(
            api_key=settings.anthropic_api_key,
            session_mgr=session_manager,
            audit_logger=logger,
        )

    if settings.llm_provider == "local_llama":
        return LocalLlamaAdapter(
            base_url=settings.local_llama_base_url,
            default_model=settings.local_llama_model,
            session_mgr=session_manager,
            audit_logger=logger,
        )

    raise RuntimeError(f"Unsupported AEGIS_LLM_PROVIDER={settings.llm_provider!r}")


async def connect_temporal_client() -> Client:
    """Create the Temporal client used by the workflow worker."""
    return await Client.connect(
        settings.temporal_host,
        data_converter=create_aegis_data_converter(),
    )


def create_worker(temporal_client: Client) -> Worker:
    """Construct the Temporal worker with all workflow activities registered."""
    audit_logger = AuditLogger("temporal-worker")
    session_mgr = SessionManager()
    budget_enforcer = BudgetEnforcer(audit_logger=audit_logger)
    loop_detector = LoopDetector(audit_logger=audit_logger)
    adapter = build_adapter(session_mgr=session_mgr, audit_logger=audit_logger)
    activities = AegisActivities(
        adapter=adapter,
        policy_engine=PolicyEngine(),
        session_mgr=session_mgr,
        budget_enforcer=budget_enforcer,
        loop_detector=loop_detector,
        audit_logger=audit_logger,
    )
    workflow_audit = WorkflowAuditActivities(audit_logger=audit_logger)

    return Worker(
        temporal_client,
        task_queue=settings.temporal_task_queue,
        workflows=[AgentTaskWorkflow],
        activities=[
            activities.pre_pii_scrub,
            activities.policy_eval,
            activities.budget_pre_check,
            activities.loop_record_step,
            activities.jit_token_issue,
            activities.llm_invoke,
            activities.budget_record_spend,
            activities.post_sanitize,
            workflow_audit.record_event,
        ],
    )


async def run_worker() -> None:
    """Run the Temporal worker until the process is terminated."""
    client = await connect_temporal_client()
    async with create_worker(client):
        await asyncio.Event().wait()


def main() -> None:
    """CLI entrypoint for `python -m src.control_plane.worker`."""
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
