# Runbook: Budget Exceeded

**Severity:** High  
**Alert source:** Prometheus alert `BudgetCritical` or `budget.exceeded` audit event  
**Primary on-call role:** Platform Engineer / AI Operations

---

## Symptoms

One or more of the following:

- Prometheus alert `BudgetCritical` fires: `aegis_budget_remaining_usd < 1.0`
- Audit log contains a `budget.exceeded` warning event
- An agent task returns HTTP 400 with body referencing `BudgetExceededError`
- A Temporal workflow transitions to `PendingApproval` / `human_intervention_required`

---

## Immediate Triage (< 5 minutes)

### 1. Identify the affected session

```bash
# Search audit logs for budget.exceeded events in the last hour
docker logs aegis-api --since 1h 2>&1 | grep "budget.exceeded"

# Expected output (JSON — extract session_id):
# {"event": "budget.exceeded", "session_id": "3fa85f64-...", "message": "Session 3fa85f64 exceeded budget ($10.0042 > $10.0000)", ...}
```

Note the `session_id` and `agent_type` from the log entry.

### 2. Check current spend for the session

```python
# Run in a Python shell connected to the running process, or query Prometheus:
from uuid import UUID
from src.watchdog.budget_enforcer import BudgetEnforcer

enforcer = BudgetEnforcer()  # replace with the running instance reference
session = enforcer.get_session(UUID("<session_id>"))
if session:
    print(f"Agent type: {session.agent_type}")
    print(f"Tokens used: {session.tokens_used:,}")
    print(f"Cost: ${session.cost_usd:.6f} / ${session.budget_limit_usd:.2f}")
    print(f"Alerts: {session.alerts}")
```

Alternatively, query Prometheus directly:

```bash
# Check remaining budget gauge for the session
curl -s "http://localhost:9090/api/v1/query?query=aegis_budget_remaining_usd" | jq .
```

### 3. Determine if the overage is legitimate

Review the audit log events for the `session_id` to assess whether the agent was performing valid work or entered an anomalous loop:

```bash
docker logs aegis-api --since 1h 2>&1 | grep "<session_id>"
```

Look for:
- **High step count with PROGRESS signals** → legitimate long-running task; consider a budget extension
- **Repeated identical tool calls** → possible loop; escalate to loop detection runbook
- **Token velocity spikes** → possible malformed prompt or adversarial input; investigate the prompt

---

## Decision Tree

```
budget.exceeded event received
        │
        ├── Was real work completed? (PROGRESS signals present)
        │         │
        │         ├── YES → Is the task genuinely unfinished?
        │         │              │
        │         │              ├── YES → Request budget extension (see below)
        │         │              └── NO  → Task is complete; close the session
        │         │
        │         └── NO → Possible loop or abuse → See loop-detected.md runbook
        │
        └── Was it a one-off spike? (single step with extreme token count)
                   │
                   ├── YES → Review the prompt for injection or malformed input
                   └── NO  → Investigate the agent implementation for infinite loops
```

---

## Budget Extension Process

Budget extensions are governed by `policies/budget.rego`:

| Requested Amount | Required Approver Role |
|---|---|
| ≤ $50 | `manager` |
| $50 – $500 | `manager` (hard cap applies at task level) |
| > $500 | `executive` |

Extensions are **not available** for `legal` or `general` agent types.

### Phase 1 (manual fallback)

1. Confirm with the task owner that the additional spend is authorized.
2. Record the approval in your ticketing system (include `session_id`, approver, approved amount, justification).
3. Create a new task request with a higher `budget_limit_usd` in the metadata and issue a fresh session token.
4. Record an `AuditEvent` with `action: "budget.extension_approved"`, `outcome: "success"`, and the approval metadata.

### Phase 2 (live HITL via Temporal)

The current implementation pauses the workflow in `PendingApproval` once the
budget review gate is reached. Approvers act on the task directly:

- `POST /api/v1/tasks/{task_id}/approve`
- `POST /api/v1/tasks/{task_id}/deny`

Only an admin JIT token with the corresponding `hitl:approve` or `hitl:deny`
action may resolve the gate.

## HITL Approval Flow

1. Identify the blocked `task_id` from the audit event, alert, or task owner.
2. Confirm in Temporal UI that the workflow is in `PendingApproval`.
3. If the spend extension is justified, approve it:

```bash
curl -s -X POST "http://localhost:18000/api/v1/tasks/${TASK_ID}/approve" \
    -H "Authorization: Bearer ${ADMIN_JIT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"approver_id":"admin-user","reason":"Budget extension approved"}'
```

4. If the work should be terminated, deny it:

```bash
curl -s -X POST "http://localhost:18000/api/v1/tasks/${TASK_ID}/deny" \
    -H "Authorization: Bearer ${ADMIN_JIT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"approver_id":"admin-user","reason":"Budget extension denied"}'
```

5. Re-check Temporal UI and the audit trail to confirm the workflow left
     `PendingApproval`.

If the request returns `409`, the task exists but is no longer awaiting
approval and may already be timed out, denied, or completed. A `404` means the
task could not be resolved at all.

---

## Post-Incident Actions

- [ ] Confirm the affected session is closed and no further charges are being incurred.
- [ ] Record the incident in the audit log: `action: "incident.budget_exceeded"`, `outcome: "success"` once resolved.
- [ ] If the overage was due to a programming error in the agent, file a bug report with the relevant `task_id` and token trace.
- [ ] If this is the second occurrence for the same `agent_type` within 7 days, review whether the default `AEGIS_BUDGET_LIMIT_USD` should be raised for that type, or whether the agent needs a code fix.
- [ ] Update Prometheus alerting thresholds if the alert fired on a known high-cost workload (raise the `BudgetCritical` threshold for that agent type using label-based alert configuration).

---

## Escalation

| Condition | Escalate To |
|---|---|
| Overage > 200% of limit | Engineering Lead + Finance |
| Suspected prompt injection or adversarial input | Security Team |
| Multiple sessions from the same `requester_id` exceeding budget | Security Team (possible abuse) |
| OPA extension policy not evaluating correctly | Platform Engineering |
