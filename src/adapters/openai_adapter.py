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

"""OpenAI adapter for Aegis-OS MCP (Model Context Protocol) integration."""

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


class OpenAIAdapter(BaseAdapter):
    """Adapter for the OpenAI Chat Completions API.

    Requires an ``api_key`` passed at construction time.  Never store API keys
    in source code - retrieve them from HashiCorp Vault at runtime.
    """

    BASE_URL = "https://api.openai.com/v1"

    def __init__(
        self,
        api_key: str,
        default_model: str = "gpt-4o-mini",
        session_mgr: SessionManager | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self._api_key = api_key
        self._default_model = default_model
        self._session_mgr = session_mgr if session_mgr is not None else SessionManager()
        self._audit = audit_logger if audit_logger is not None else AuditLogger("openai-adapter")

    @property
    def provider_name(self) -> str:
        return "openai"

    def outbound_request_binding(self, request: LLMRequest) -> tuple[str, str] | None:
        return ("POST", f"{self.BASE_URL}/chat/completions")

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a chat completion request to OpenAI."""
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

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
            response.raise_for_status()
            body = response.json()

        choice = body["choices"][0]
        return LLMResponse(
            content=choice["message"]["content"],
            tokens_used=body["usage"]["total_tokens"],
            model=model,
            provider=self.provider_name,
            finish_reason=choice.get("finish_reason", "stop"),
        )
