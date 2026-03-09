"""Startup wiring tests for live HITL endpoint configuration."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import src.main as main_module
from src.control_plane.approval_service import TaskApprovalService
from src.governance.policy_engine.opa_client import PolicyEngine
from src.governance.session_mgr import SessionManager


@pytest.mark.asyncio
async def test_startup_event_configures_hitl_controls(monkeypatch: pytest.MonkeyPatch) -> None:
    """App startup must connect Temporal and wire configure_hitl_controls()."""
    fake_client = SimpleNamespace()
    connect_mock = AsyncMock(return_value=fake_client)
    configure_mock = MagicMock()

    monkeypatch.setattr(main_module, "_connect_temporal_client", connect_mock)
    monkeypatch.setattr(main_module, "configure_hitl_controls", configure_mock)
    monkeypatch.setattr(main_module, "PolicyEngine", MagicMock(spec=PolicyEngine))
    monkeypatch.setattr(main_module, "SessionManager", MagicMock(spec=SessionManager))

    await main_module.startup_event()

    connect_mock.assert_awaited_once()
    configure_mock.assert_called_once()
    kwargs = configure_mock.call_args.kwargs
    assert isinstance(kwargs["approval_service"], TaskApprovalService)
    assert kwargs["policy_engine"] is main_module.app.state.hitl_policy_engine
    assert kwargs["session_mgr"] is main_module.app.state.hitl_session_mgr
    assert main_module.app.state.temporal_client is fake_client
