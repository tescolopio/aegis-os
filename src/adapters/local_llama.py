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

"""Local Llama adapter for Aegis-OS MCP (Model Context Protocol) integration.

Communicates with a locally running Ollama or llama.cpp server that exposes
an OpenAI-compatible ``/v1/chat/completions`` endpoint.
"""

import httpx

from src.adapters.base import (
    AdapterSecurityError,
    BaseAdapter,
    LLMRequest,
    LLMResponse,
    require_sender_constrained_request,
)
from src.audit_vault.logger import AuditLogger
from src.governance.session_mgr import DPoPReplayError, SessionManager


class LocalLlamaAdapter(BaseAdapter):
    """Adapter for a locally-hosted Llama model served via Ollama or llama.cpp.

    The local server must expose an OpenAI-compatible API at ``base_url``.
    No API key is required for local deployments.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        default_model: str = "llama3",
        session_mgr: SessionManager | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._default_model = default_model
        self._session_mgr = session_mgr if session_mgr is not None else SessionManager()
        self._audit = (
            audit_logger if audit_logger is not None else AuditLogger("local-llama-adapter")
        )

    @property
    def provider_name(self) -> str:
        return "local_llama"

    def outbound_request_binding(self, request: LLMRequest) -> tuple[str, str] | None:
        return ("POST", f"{self._base_url}/chat/completions")

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a chat completion request to the local Llama server."""
        binding = self.outbound_request_binding(request)
        if binding is not None:
            method, url = binding
            try:
                claims = require_sender_constrained_request(
                    request,
                    session_mgr=self._session_mgr,
                    http_method=method,
                    http_url=url,
                )
            except AdapterSecurityError as exc:
                token = request.metadata.get("aegis_token", "")
                task_id = "unknown"
                agent_type = "unknown"
                if token:
                    try:
                        token_claims = self._session_mgr.validate_token(token)
                        task_id = token_claims.task_id or "unknown"
                        agent_type = token_claims.agent_type
                    except Exception:
                        pass
                event_name = (
                    "dpop.proof.replayed"
                    if isinstance(exc.__cause__, DPoPReplayError)
                    else "dpop.proof.rejected"
                )
                self._audit.stage_event(
                    event_name,
                    outcome="deny",
                    stage="llm-invoke",
                    task_id=task_id,
                    agent_type=agent_type,
                    provider=self.provider_name,
                    error_message=str(exc),
                )
                raise
            if claims is not None:
                self._audit.stage_event(
                    "dpop.proof.validated",
                    outcome="allow",
                    stage="llm-invoke",
                    task_id=claims.task_id or "unknown",
                    agent_type=claims.agent_type,
                    provider=self.provider_name,
                    jti=claims.jti,
                )

        model = request.model or self._default_model
        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                url,
                json=payload,
            )
            response.raise_for_status()
            body = response.json()

        choice = body["choices"][0]
        usage = body.get("usage", {})
        tokens_used = usage.get("total_tokens", 0)

        return LLMResponse(
            content=choice["message"]["content"],
            tokens_used=tokens_used,
            model=model,
            provider=self.provider_name,
            finish_reason=choice.get("finish_reason", "stop"),
        )
