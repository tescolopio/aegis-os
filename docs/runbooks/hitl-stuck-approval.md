# Runbook: HITL Approval Workflow Stuck

**Alert**: `aegis_hitl_stuck`  
**Severity**: Critical  
**Metric**: `aegis_workflow_pending_approval_seconds > 86400`

---

## Symptoms

- Prometheus alert `aegis_hitl_stuck` fires.
- `aegis_workflow_pending_approval_seconds{workflow_id="..."}` exceeds 86 400 (24 hours).
- Temporal UI (http://localhost:18080) shows a workflow in `PendingApproval` state with no recent signal activity.
- Downstream tasks that depend on the approval are blocked.

---

## Diagnosis

### 1. Confirm the stack is reachable

```bash
curl -f http://localhost:18000/health
```

### 2. Confirm the alert is active

```bash
curl -s http://localhost:19090/api/v1/rules | jq '.data.groups[] | select(.name == "aegis_hitl")'
```

### 3. Identify the affected `task_id`

Use the alert labels, audit trail, or the Temporal UI workflow list. In the
current Phase 2 implementation the workflow ID is the task ID.

### 4. Inspect the workflow in Temporal

- Open `http://localhost:18080`.
- Find the workflow whose ID matches the `task_id`.
- Confirm the current state is `PendingApproval` rather than `completed`,
	`denied`, or `failed`.
- Check whether recent signals are missing or whether the workflow has already
	timed out.

### 5. Determine the failure mode

- Missing approver: workflow is still `PendingApproval` and no approve/deny
	signal appears in Temporal history.
- Session or RBAC issue: operators report `401` or `403` from the REST endpoint.
- Timed out workflow: the workflow already emitted `workflow.timed_out` and the
	API now returns `409 pending_approval_conflict` for late approval attempts.
- Worker/process issue: the API is reachable, but the workflow does not move
	after a valid signal because the worker hosting the workflow is not running.

---

## Escalation

Escalate with the following bundle of information:

- `task_id`
- current Temporal workflow status
- time spent in `PendingApproval`
- last audit event seen for the task
- whether the approve/deny endpoint returned `200`, `401`, `403`, or `404`

Escalation path:

- Page the platform or workflow on-call if the worker process is down or the
	workflow does not move after a valid signal.
- Page security/governance if a valid admin operator is getting repeated `403`
	OPA denials or cross-session rejections.
- Escalate to the task owner or operational approver if no authorised reviewer
	is available and the task is business-critical.

---

## Resolution

### Approve via REST

```bash
curl -s -X POST "http://localhost:18000/api/v1/tasks/${TASK_ID}/approve" \
	-H "Authorization: Bearer ${ADMIN_JIT_TOKEN}" \
	-H "Content-Type: application/json" \
	-d '{"approver_id":"admin-user","reason":"Approved after review"}'
```

### Deny via REST

```bash
curl -s -X POST "http://localhost:18000/api/v1/tasks/${TASK_ID}/deny" \
	-H "Authorization: Bearer ${ADMIN_JIT_TOKEN}" \
	-H "Content-Type: application/json" \
	-d '{"approver_id":"admin-user","reason":"Denied after review"}'
```

Expected outcomes:

- `200`: signal accepted; re-check Temporal UI and audit logs.
- `401`: token missing, malformed, expired, or revoked.
- `403`: token action missing, wrong session, or OPA RBAC denied the action.
- `404`: no workflow exists for that `task_id`.
- `409`: workflow exists but is no longer awaiting approval.

If the workflow remains stuck after a valid `200` response:

1. Restart the process hosting the Temporal worker.
2. Re-open Temporal UI and verify the signal is present in history.
3. Confirm the workflow transitions out of `PendingApproval`.

---

## Post-Incident

- Confirm the workflow left `PendingApproval` in Temporal UI.
- Confirm the audit trail contains one of:
	- `workflow.approved`
	- `workflow.denied`
	- `workflow.timed_out`
- If you restarted the worker, confirm `docker-compose logs aegis-worker` shows
	the worker reconnected to Temporal successfully.
- Confirm downstream task processing resumed or the task was intentionally
	terminated.
- Confirm the alert resolved in Prometheus after the workflow state changed.
