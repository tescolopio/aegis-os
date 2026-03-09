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

"""Aegis-OS configuration settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="AEGIS_", case_sensitive=False)

    aegis_env: str = "development"
    vault_addr: str = "http://localhost:8200"
    vault_token: str = "aegis-dev-root-token"
    temporal_host: str = "localhost:7233"
    temporal_task_queue: str = "aegis-agent-tasks"
    opa_url: str = "http://localhost:8181"

    # Worker / adapter settings
    llm_provider: str = "local_llama"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    local_llama_base_url: str = "http://host.docker.internal:11434/v1"
    local_llama_model: str = "llama3"

    # Token settings
    token_expiry_seconds: int = 900  # 15 minutes
    token_secret_key: str = "change-me-in-production-use-a-strong-random-key"
    token_algorithm: str = "HS256"
    token_private_key: str = ""
    token_public_key: str = ""
    require_sender_constrained_tokens: bool = False
    dpop_proof_ttl_seconds: int = 300
    dpop_clock_skew_seconds: int = 30
    dpop_replay_store_url: str = ""

    # Watchdog settings
    max_agent_steps: int = 10
    max_token_velocity: int = 10_000  # tokens per step
    budget_limit_usd: float = 10.0

    # Temporal encryption (P2-3)
    # URL-safe base64-encoded 32-byte Fernet key.  When empty, the data
    # converter falls back to a compile-time development key that must never
    # be used in production.
    temporal_encryption_key: str = ""


settings = Settings()
