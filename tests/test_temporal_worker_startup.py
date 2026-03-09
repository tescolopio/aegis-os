"""Worker construction and configuration tests for the Temporal runtime."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import src.control_plane.worker as worker_module
from src.adapters.local_llama import LocalLlamaAdapter


def test_build_adapter_defaults_to_local_llama(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_module.settings, "llm_provider", "local_llama")
    monkeypatch.setattr(worker_module.settings, "local_llama_base_url", "http://example/v1")
    monkeypatch.setattr(worker_module.settings, "local_llama_model", "llama3")

    adapter = worker_module.build_adapter()

    assert isinstance(adapter, LocalLlamaAdapter)


def test_build_adapter_requires_openai_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_module.settings, "llm_provider", "openai")
    monkeypatch.setattr(worker_module.settings, "openai_api_key", "")

    with pytest.raises(RuntimeError, match="AEGIS_OPENAI_API_KEY"):
        worker_module.build_adapter()


def test_create_worker_uses_configured_task_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_worker = MagicMock(name="worker")
    worker_ctor = MagicMock(return_value=fake_worker)
    build_adapter = MagicMock(return_value=MagicMock())
    monkeypatch.setattr(worker_module, "Worker", worker_ctor)
    monkeypatch.setattr(worker_module, "build_adapter", build_adapter)
    monkeypatch.setattr(worker_module.settings, "temporal_task_queue", "aegis-agent-tasks")

    client = MagicMock(name="temporal-client")
    result = worker_module.create_worker(client)

    assert result is fake_worker
    worker_ctor.assert_called_once()
    assert worker_ctor.call_args.kwargs["task_queue"] == "aegis-agent-tasks"


def test_worker_module_main_is_importable() -> None:
    assert callable(worker_module.main)
