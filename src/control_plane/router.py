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

"""Control Plane Router - decides which agent handles which sub-task.

All LLM execution MUST be routed through ``orchestrator.run()``.  Governance
modules (Guardrails, OPA, SessionManager) must never be called directly from
this module – they are the orchestrator's exclusive responsibility.
"""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, Header, HTTPException
from jose import JWTError
from pydantic import BaseModel, Field, ValidationError

from src.audit_vault.logger import AuditLogger
from src.control_plane.approval_service import (
    PendingApprovalConflictError,
    PendingApprovalNotFoundError,
    TaskApprovalService,
)
from src.control_plane.orchestrator import (
    BudgetLimitError,
    Orchestrator,
    OrchestratorRequest,
    OrchestratorResult,
)
from src.governance.policy_engine import PolicyEngine, PolicyInput
from src.governance.session_mgr import (
    SessionManager,
    TokenActionError,
    TokenExpiredError,
    TokenRevokedError,
)

router = APIRouter(tags=["control-plane"])
_logger = AuditLogger()

# Module-level orchestrator instance – set at application startup via
# ``configure_orchestrator()``.  Tests replace this with a mock.
_orchestrator: Orchestrator | None = None
_approval_service: TaskApprovalService | None = None
_approval_policy_engine: PolicyEngine | None = None
_approval_session_mgr: SessionManager | None = None


def configure_orchestrator(orc: Orchestrator) -> None:
    """Inject the orchestrator instance (called during app startup)."""
    global _orchestrator  # noqa: PLW0603
    _orchestrator = orc


def _require_orchestrator() -> Orchestrator:
    if _orchestrator is None:
        raise RuntimeError(
            "Orchestrator has not been configured.  "
            "Call configure_orchestrator() during app startup."
        )
    return _orchestrator


def configure_hitl_controls(
    *,
    approval_service: TaskApprovalService,
    policy_engine: PolicyEngine,
    session_mgr: SessionManager,
) -> None:
    """Inject approval dependencies used by the HITL approve/deny endpoints."""
    global _approval_service, _approval_policy_engine, _approval_session_mgr  # noqa: PLW0603
    _approval_service = approval_service
    _approval_policy_engine = policy_engine
    _approval_session_mgr = session_mgr


def _require_hitl_controls() -> tuple[TaskApprovalService, PolicyEngine, SessionManager]:
    if (
        _approval_service is None
        or _approval_policy_engine is None
        or _approval_session_mgr is None
    ):
        raise RuntimeError(
            "HITL controls have not been configured. "
            "Call configure_hitl_controls() during app startup."
        )
    return _approval_service, _approval_policy_engine, _approval_session_mgr


class AgentType(StrEnum):
    FINANCE = "finance"
    HR = "hr"
    IT = "it"
    LEGAL = "legal"
    GENERAL = "general"


class TaskRequest(BaseModel):
    """Incoming agent task — carries everything the orchestrator pipeline needs."""

    task_id: UUID = Field(default_factory=uuid4)
    prompt: str = Field(..., min_length=1, max_length=32_768)
    description: str = Field(default="", max_length=4096)
    agent_type: AgentType = AgentType.GENERAL
    requester_id: str = Field(..., min_length=1, max_length=256)
    model: str = "gpt-4o-mini"
    max_tokens: int = 1024
    temperature: float = 0.7
    system_prompt: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)
    protect_outbound_request: bool = False


class TaskResponse(BaseModel):
    """Unified response returned from POST /tasks after full pipeline execution."""

    task_id: UUID
    agent_type: AgentType
    session_token: str
    message: str
    tokens_used: int = 0
    model: str = ""
    pii_found: list[str] = Field(default_factory=list)


class ExecuteRequest(BaseModel):
    """Request body for the LLM execution endpoint."""

    task_id: UUID = Field(default_factory=uuid4)
    prompt: str = Field(..., min_length=1, max_length=32_768)
    agent_type: AgentType = AgentType.GENERAL
    requester_id: str = Field(..., min_length=1, max_length=256)
    session_token: str | None = None
    model: str = "gpt-4o-mini"
    max_tokens: int = 1024
    temperature: float = 0.7
    system_prompt: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)
    protect_outbound_request: bool = False


class ApprovalDecisionRequest(BaseModel):
    """Request body for a HITL approve or deny action."""

    approver_id: str = Field(..., min_length=1, max_length=256)
    reason: str = Field(..., min_length=1, max_length=4096)


class ApprovalDecisionResponse(BaseModel):
    """Response body returned after a HITL decision signal is accepted."""

    task_id: UUID
    status: str
    actor_id: str
    timestamp: datetime


class StructuredErrorBody(BaseModel):
    """Documented error schema for HITL approval endpoints."""

    error: dict[str, str]


def _error_response(
    status_code: int,
    *,
    code: str,
    message: str,
    task_id: UUID,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={
            "error": {
                "code": code,
                "message": message,
                "task_id": str(task_id),
            }
        },
    )


def _extract_bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return token


async def _authorize_hitl_action(
    *,
    task_id: UUID,
    action: str,
    authorization: str | None,
) -> tuple[PolicyInput, str]:
    approval_service, policy_engine, session_mgr = _require_hitl_controls()
    token = _extract_bearer_token(authorization)

    try:
        claims = session_mgr.validate_token(token)
        session_mgr.ensure_action_allowed(claims, f"hitl:{action}")
    except TokenExpiredError as exc:
        _logger.warning("jit.expired", task_id=str(task_id), action=action)
        raise HTTPException(status_code=401, detail="JIT token expired") from exc
    except TokenRevokedError as exc:
        _logger.warning("jit.revoked", task_id=str(task_id), action=action)
        raise HTTPException(status_code=401, detail="JIT token revoked") from exc
    except TokenActionError as exc:
        _logger.warning("jit.action_denied", task_id=str(task_id), action=action)
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except JWTError as exc:
        _logger.warning("jit.invalid", task_id=str(task_id), action=action)
        raise HTTPException(status_code=401, detail="Malformed or invalid JIT token") from exc

    snapshot = await approval_service.get_snapshot(task_id)
    if (
        claims.session_id is not None
        and snapshot.session_id is not None
        and claims.session_id != snapshot.session_id
    ):
        _logger.warning(
            "audit.cross_session_attempt",
            task_id=str(task_id),
            action=action,
            token_session_id=claims.session_id,
            workflow_session_id=snapshot.session_id,
        )
        raise HTTPException(status_code=403, detail="Token session does not match task session")

    policy_input = PolicyInput(
        agent_type=snapshot.agent_type,
        requester_id=claims.sub,
        action=action,
        resource="workflow:pending_approval",
        principal_role=claims.role,
        token_expired=False,
        metadata=claims.metadata,
    )
    result = await policy_engine.evaluate("agent_access", policy_input)
    if not result.allowed:
        _logger.warning(
            "hitl.rbac_denied",
            task_id=str(task_id),
            action=action,
            role=claims.role or "",
            reasons=result.reasons,
        )
        raise HTTPException(status_code=403, detail="OPA denied HITL action")

    return policy_input, claims.sub


def _parse_approval_request(
    raw_request: dict[str, object], *, task_id: UUID
) -> ApprovalDecisionRequest:
    """Validate an approve/deny request body and surface errors as HTTP 400."""
    try:
        return ApprovalDecisionRequest.model_validate(raw_request)
    except ValidationError as exc:
        raise _error_response(
            400,
            code="invalid_request",
            message=f"Invalid approval request body: {exc.errors()}",
            task_id=task_id,
        ) from exc


@router.post("/tasks", response_model=TaskResponse)
async def route_task(request: TaskRequest) -> TaskResponse:
    """Execute a task through the full governance pipeline and return the LLM result.

    All governance enforcement (PII scrubbing, OPA policy evaluation, JIT session
    token issuance) is performed exclusively by the orchestrator.  This handler
    must not call any governance module directly.
    """
    orc = _require_orchestrator()

    _logger.info(
        "task.routing",
        task_id=str(request.task_id),
        agent_type=request.agent_type,
        requester_id=request.requester_id,
    )

    try:
        result: OrchestratorResult = await orc.run(
            OrchestratorRequest(
                task_id=request.task_id,
                prompt=request.prompt,
                agent_type=request.agent_type.value,
                requester_id=request.requester_id,
                model=request.model,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                system_prompt=request.system_prompt,
                metadata=request.metadata,
                protect_outbound_request=request.protect_outbound_request,
            )
        )
    except BudgetLimitError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.error(
            "task.error",
            task_id=str(request.task_id),
            error=str(exc),
        )
        raise HTTPException(status_code=500, detail="Internal pipeline error") from exc

    _logger.info(
        "task.routed",
        task_id=str(request.task_id),
        agent_type=request.agent_type,
    )

    return TaskResponse(
        task_id=result.task_id,
        agent_type=request.agent_type,
        session_token=result.session_token,
        message=result.response.content,
        tokens_used=result.response.tokens_used,
        model=result.response.model,
        pii_found=list(
            dict.fromkeys(result.pii_found_in_prompt + result.pii_found_in_response)
        ),
    )


@router.post("/tasks/execute", response_model=OrchestratorResult)
async def execute_task(request: ExecuteRequest) -> OrchestratorResult:
    """Execute a task through the full orchestration pipeline.

    All governance enforcement (PII scrubbing, policy evaluation, session token
    issuance) is handled exclusively by the orchestrator.  This handler must
    not call any governance module directly.
    """
    orc = _require_orchestrator()

    _logger.info(
        "task.execute",
        task_id=str(request.task_id),
        agent_type=request.agent_type,
        requester_id=request.requester_id,
    )

    try:
        result: OrchestratorResult = await orc.run(
            OrchestratorRequest(
                task_id=request.task_id,
                prompt=request.prompt,
                agent_type=request.agent_type.value,
                requester_id=request.requester_id,
                session_token=request.session_token,
                model=request.model,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                system_prompt=request.system_prompt,
                metadata=request.metadata,
                protect_outbound_request=request.protect_outbound_request,
            )
        )
    except BudgetLimitError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.error(
            "task.execute.error",
            task_id=str(request.task_id),
            error=str(exc),
        )
        raise HTTPException(status_code=500, detail="Internal pipeline error") from exc

    return result


@router.get("/tasks/{task_id}")
async def get_task_status(task_id: UUID) -> dict[str, str]:
    """Get the status of a routed task."""
    return {"task_id": str(task_id), "status": "pending"}


@router.post("/tasks/{task_id}/approve", response_model=ApprovalDecisionResponse)
async def approve_task(
    task_id: UUID,
    raw_request: dict[str, object] = Body(...),
    authorization: str | None = Header(default=None),
) -> ApprovalDecisionResponse:
    """Approve a task currently waiting in the PendingApproval workflow state."""
    approval_service, _, _ = _require_hitl_controls()
    request = _parse_approval_request(raw_request, task_id=task_id)
    try:
        await _authorize_hitl_action(task_id=task_id, action="approve", authorization=authorization)
        result = await approval_service.approve(task_id, request.approver_id, request.reason)
    except PendingApprovalConflictError as exc:
        raise _error_response(
            409,
            code="pending_approval_conflict",
            message=str(exc),
            task_id=task_id,
        ) from exc
    except PendingApprovalNotFoundError as exc:
        raise _error_response(
            404,
            code="pending_approval_not_found",
            message=str(exc),
            task_id=task_id,
        ) from exc

    return ApprovalDecisionResponse(
        task_id=task_id,
        status=result.status,
        actor_id=result.actor_id,
        timestamp=datetime.now(tz=UTC),
    )


@router.post("/tasks/{task_id}/deny", response_model=ApprovalDecisionResponse)
async def deny_task(
    task_id: UUID,
    raw_request: dict[str, object] = Body(...),
    authorization: str | None = Header(default=None),
) -> ApprovalDecisionResponse:
    """Deny a task currently waiting in the PendingApproval workflow state."""
    approval_service, _, _ = _require_hitl_controls()
    request = _parse_approval_request(raw_request, task_id=task_id)
    try:
        await _authorize_hitl_action(task_id=task_id, action="deny", authorization=authorization)
        result = await approval_service.deny(task_id, request.approver_id, request.reason)
    except PendingApprovalConflictError as exc:
        raise _error_response(
            409,
            code="pending_approval_conflict",
            message=str(exc),
            task_id=task_id,
        ) from exc
    except PendingApprovalNotFoundError as exc:
        raise _error_response(
            404,
            code="pending_approval_not_found",
            message=str(exc),
            task_id=task_id,
        ) from exc

    return ApprovalDecisionResponse(
        task_id=task_id,
        status=result.status,
        actor_id=result.actor_id,
        timestamp=datetime.now(tz=UTC),
    )
