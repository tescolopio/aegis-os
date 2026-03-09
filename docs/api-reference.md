# Aegis-OS API Reference

**Version**: 0.2.0 (current)  
**Base URL**: `http://localhost:18000` (local dev)  
**Format**: All request and response bodies are JSON.

> This document reflects the live local FastAPI contract as of 2026-03-07.
> Where the implementation still differs from the Gate 2 target contract,
> this document describes the current behavior rather than the roadmap ideal.

---

## Table of Contents

- [Core Task Endpoints](#core-task-endpoints)
  - [POST /api/v1/tasks](#post-apiv1tasks)
  - [GET /api/v1/tasks/{task_id}](#get-apiv1taskstask_id)
- [HITL Approval Endpoints](#hitl-approval-endpoints)
  - [POST /api/v1/tasks/{task_id}/approve](#post-apiv1taskstask_idapprove)
  - [POST /api/v1/tasks/{task_id}/deny](#post-apiv1taskstask_iddeny)
- [Health](#health)

---

## Core Task Endpoints

### POST /api/v1/tasks

Submit a new agent task to the Aegis Governance Loop.

**Request body**

```json
{
  "prompt": "Summarise the Q1 audit findings.",
  "agent_type": "finance",
  "requester_id": "alice@example.com",
  "protect_outbound_request": true
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `prompt` | string | yes | The raw task prompt. PII is scrubbed before reaching the LLM. |
| `agent_type` | string | yes | One of the registered agent types (`finance`, `hr`, `it`, `legal`, `general`, `code_scalpel`). |
| `requester_id` | string | yes | Stable identity of the requesting user or service. |
| `protect_outbound_request` | boolean | no | When `true`, Aegis issues a sender-constrained adapter token and DPoP proof for the outbound provider call instead of using a bearer-only adapter credential. |
| `budget_session_id` | UUID string | no | If omitted, a new budget session is created automatically. |

**Response `200 OK`**

```json
{
  "task_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "message": "Q1 audit findings summary...",
  "model": "gpt-4o-mini",
  "tokens_used": 312,
  "agent_type": "finance",
  "session_token": "eyJhbGciOi..."
}
```

**Notes**

- `protect_outbound_request=true` affects the adapter-bound provider call, not
  the HTTP response contract. The returned `session_token` remains the caller's
  normal Aegis session token.
- Protected outbound requests emit additional audit events such as
  `token.sender_constrained_issued`, `dpop.proof.validated`, and
  `dpop.proof.replayed`.

**Error responses**

| Status | Condition |
|---|---|
| `400` | Invalid request body or unknown `agent_type`. |
| `403` | OPA policy denied the request. |
| `402` | Budget cap exceeded for the session. |
| `500` | Internal server error (stage exception). |

---

### GET /api/v1/tasks/{task_id}

Retrieve the result and audit trail for a previously submitted task.

_Endpoint not yet implemented — placeholder for Phase 2._

---

## HITL Approval Endpoints

These endpoints are live and operate on `task_id`, not `workflow_id`.
They signal a Temporal workflow that is currently in `PendingApproval`.

**Authorization**

- Caller must supply `Authorization: Bearer <jit-token>`.
- The token must be valid, unrevoked, and scoped to `hitl:approve` or
  `hitl:deny`.
- The live RBAC matrix currently allows only `role=admin` to approve or deny.
- Authorization is OPA-gated against resource `workflow:pending_approval`.

**Timeout behavior**

- The timeout is enforced inside the Temporal workflow by
  `approval_timeout_seconds`.
- Once the approval window has expired, the workflow still resolves by
  `task_id`, but it is no longer in `awaiting-approval` state.
- In the current implementation, a late approve or deny request therefore
  returns `409` with error code `pending_approval_conflict`.

---

### POST /api/v1/tasks/{task_id}/approve

Approve a task whose workflow is waiting in `PendingApproval` state.

**Path parameters**

| Parameter | Description |
|---|---|
| `task_id` | UUID of the task whose workflow is currently awaiting approval. |

**Request example**

```json
{
  "approver_id": "admin-user",
  "reason": "Reviewed output; no policy violation found."
}
```

**Approve request schema**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ApproveTaskRequest",
  "type": "object",
  "additionalProperties": false,
  "required": ["approver_id", "reason"],
  "properties": {
    "approver_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "reason": {
      "type": "string",
      "minLength": 1,
      "maxLength": 4096
    }
  }
}
```

**Response example `200 OK`**

```json
{
  "task_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "approved",
  "actor_id": "admin-user",
  "timestamp": "2026-03-05T12:00:00Z"
}
```

**Approve response schema**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ApproveTaskResponse",
  "type": "object",
  "additionalProperties": false,
  "required": ["task_id", "status", "actor_id", "timestamp"],
  "properties": {
    "task_id": {
      "type": "string",
      "format": "uuid"
    },
    "status": {
      "type": "string",
      "enum": ["approved"]
    },
    "actor_id": {
      "type": "string"
    },
    "timestamp": {
      "type": "string",
      "format": "date-time"
    }
  }
}
```

**Error responses**

| Status | Condition |
|---|---|
| `400` | Request body failed validation. |
| `401` | Missing, malformed, expired, or revoked JIT token. |
| `403` | Token session mismatch, missing `hitl:approve` action, or OPA RBAC deny. |
| `404` | No workflow exists for the given `task_id`. |
| `409` | Workflow exists but is no longer awaiting approval, including timed-out tasks. |
| `500` | Internal server error while resolving approval dependencies. |

---

### POST /api/v1/tasks/{task_id}/deny

Deny a task whose workflow is waiting in `PendingApproval` state.

**Path parameters**

| Parameter | Description |
|---|---|
| `task_id` | UUID of the task whose workflow is currently awaiting approval. |

**Request example**

```json
{
  "approver_id": "admin-user",
  "reason": "Output contains policy violation; denying continuation."
}
```

**Deny request schema**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "DenyTaskRequest",
  "type": "object",
  "additionalProperties": false,
  "required": ["approver_id", "reason"],
  "properties": {
    "approver_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "reason": {
      "type": "string",
      "minLength": 1,
      "maxLength": 4096
    }
  }
}
```

**Response example `200 OK`**

```json
{
  "task_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "denied",
  "actor_id": "admin-user",
  "timestamp": "2026-03-05T12:01:00Z"
}
```

**Deny response schema**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "DenyTaskResponse",
  "type": "object",
  "additionalProperties": false,
  "required": ["task_id", "status", "actor_id", "timestamp"],
  "properties": {
    "task_id": {
      "type": "string",
      "format": "uuid"
    },
    "status": {
      "type": "string",
      "enum": ["denied"]
    },
    "actor_id": {
      "type": "string"
    },
    "timestamp": {
      "type": "string",
      "format": "date-time"
    }
  }
}
```

**Structured error schema**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "PendingApprovalError",
  "type": "object",
  "additionalProperties": false,
  "required": ["detail"],
  "properties": {
    "detail": {
      "type": "object",
      "additionalProperties": false,
      "required": ["error"],
      "properties": {
        "error": {
          "type": "object",
          "additionalProperties": false,
          "required": ["code", "message", "task_id"],
          "properties": {
            "code": {
              "type": "string"
            },
            "message": {
              "type": "string"
            },
            "task_id": {
              "type": "string",
              "format": "uuid"
            }
          }
        }
      }
    }
  }
}
```

**Error responses**

| Status | Condition |
|---|---|
| `400` | Request body failed validation. |
| `401` | Missing, malformed, expired, or revoked JIT token. |
| `403` | Token session mismatch, missing `hitl:deny` action, or OPA RBAC deny. |
| `404` | No workflow exists for the given `task_id`. |
| `409` | Workflow exists but is no longer awaiting approval, including timed-out tasks. |
| `500` | Internal server error while resolving approval dependencies. |

---

## Health

### GET /health

Returns `{"status": "ok"}` with HTTP 200 when the API is ready. Used by
Docker Compose `healthcheck` and load balancer probes.
