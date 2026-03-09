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

"""Replay-store implementations for DPoP proof ``jti`` tracking."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any


class DPoPReplayStore(ABC):
    """Abstract store for DPoP proof ``jti`` replay protection."""

    @abstractmethod
    def register_if_unused(self, jti: str, ttl_seconds: int) -> bool:
        """Register ``jti`` for ``ttl_seconds`` and return ``False`` on replay."""


class InMemoryDPoPReplayStore(DPoPReplayStore):
    """Development-only in-memory replay store.

    This store is process-local and therefore unsuitable for multi-replica
    production deployment. It remains useful for tests and local development.
    """

    def __init__(self) -> None:
        self._entries: dict[str, float] = {}

    def register_if_unused(self, jti: str, ttl_seconds: int) -> bool:
        now = time.time()
        expired = [key for key, expires_at in self._entries.items() if expires_at <= now]
        for key in expired:
            self._entries.pop(key, None)
        if jti in self._entries:
            return False
        self._entries[jti] = now + ttl_seconds
        return True


class RedisDPoPReplayStore(DPoPReplayStore):
    """Redis-backed replay store using TTL keys for DPoP proof ``jti`` values."""

    def __init__(
        self,
        redis_url: str,
        *,
        namespace: str = "aegis:dpop:jti",
        client: Any | None = None,
    ) -> None:
        if client is not None:
            self._client = client
        else:
            try:
                from redis import Redis
            except ImportError as exc:
                raise RuntimeError(
                    "redis package is required for RedisDPoPReplayStore; install the project "
                    "dependencies or provide an explicit Redis client"
                ) from exc
            self._client = Redis.from_url(redis_url)
        self._namespace = namespace

    def register_if_unused(self, jti: str, ttl_seconds: int) -> bool:
        key = f"{self._namespace}:{jti}"
        result = self._client.set(key, "1", ex=ttl_seconds, nx=True)
        return bool(result)
