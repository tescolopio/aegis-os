"""Tests for the shared DPoP replay-store implementations."""

from __future__ import annotations

import pytest

from src.config import settings
from src.governance.replay_store import RedisDPoPReplayStore
from src.governance.session_mgr import SessionManager


class _FakeRedis:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int, bool]] = []
        self._used: set[str] = set()

    def set(self, key: str, value: str, ex: int, nx: bool) -> bool | None:
        self.calls.append((key, value, ex, nx))
        if key in self._used:
            return None
        self._used.add(key)
        return True


def test_redis_replay_store_uses_ttl_and_nx() -> None:
    fake = _FakeRedis()
    store = RedisDPoPReplayStore("redis://unused", client=fake)

    assert store.register_if_unused("proof-1", 300) is True
    assert store.register_if_unused("proof-1", 300) is False
    assert fake.calls[0] == ("aegis:dpop:jti:proof-1", "1", 300, True)


def test_session_manager_requires_shared_replay_store_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "aegis_env", "production")
    monkeypatch.setattr(settings, "dpop_replay_store_url", "")

    with pytest.raises(ValueError, match="AEGIS_DPOP_REPLAY_STORE_URL"):
        SessionManager()
