"""Integration tests for the Redis-backed DPoP replay store."""

from __future__ import annotations

import pytest

from src.governance.replay_store import RedisDPoPReplayStore


@pytest.mark.integration
def test_redis_replay_store_rejects_duplicate_proof_jti() -> None:
    try:
        from redis import Redis
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs
    except ImportError:
        pytest.skip("redis or testcontainers not installed; skipping live Redis replay-store test")

    container = DockerContainer("redis:7-alpine")
    container.with_exposed_ports(6379)

    try:
        container.start()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Docker unavailable - skipping live Redis replay-store test: {exc}")

    try:
        wait_for_logs(container, "Ready to accept connections", timeout=30)
    except Exception:  # noqa: BLE001
        container.stop()
        pytest.skip("Redis container did not become ready in time; skipping")

    port = container.get_exposed_port(6379)
    redis_url = f"redis://localhost:{port}/0"

    try:
        client = Redis.from_url(redis_url)
        client.ping()
        store = RedisDPoPReplayStore(redis_url)
        assert store.register_if_unused("proof-live-1", 300) is True
        assert store.register_if_unused("proof-live-1", 300) is False
    finally:
        container.stop()
