# Runbook: Loop Detected / Human Intervention Required

**Severity:** High  
**Alert source:** `loop_detector.no_progress` or `loop_detector.velocity_exceeded` audit event; `WorkflowStatus.HUMAN_INTERVENTION_REQUIRED` in Temporal UI  
**Primary on-call role:** Platform Engineer / AI Operations

---

## Symptoms

One or more of the following:

- Audit log contains `loop_detector.no_progress` or `loop_detector.velocity_exceeded` warning events
- A Temporal workflow is stuck in `HUMAN_INTERVENTION_REQUIRED` state (visible in Temporal UI at `http://localhost:8080`)
- An agent task stops making forward progress; the task owner reports no completion
- Prometheus shows elevated `aegis_tokens_consumed_total` for an `agent_type` with no corresponding task completion

---

## Background: Circuit Breaker Thresholds

The `LoopDetector` triggers under two conditions:

| Condition | Threshold (default) | Config Variable |
|---|---|---|
| No `PROGRESS` signal for N consecutive steps | 10 steps | `AEGIS_MAX_AGENT_STEPS` |
| Single step token consumption > N tokens | 10,000 tokens | `AEGIS_MAX_TOKEN_VELOCITY` |

Both raise `LoopDetectedError` and set `ExecutionContext.intervention_required = True`.

---

## Immediate Triage (< 5 minutes)

### 1. Identify the affected session

```bash
# Find loop detection events in the last hour
docker logs aegis-api --since 1h 2>&1 | grep -E "loop_detector\.(no_progress|velocity_exceeded)"

# Expected output:
# {"event": "loop_detector.no_progress", "session_id": "abc123", "step": 10, "streak": 10, ...}
```

Note the `session_id`, `step` count, and trigger type (`no_progress` vs `velocity_exceeded`).

### 2. Inspect the execution context

```python
from uuid import UUID
from src.watchdog.loop_detector import LoopDetector, LoopSignal

detector = LoopDetector()  # replace with the running instance reference
ctx = detector.get_context(UUID("<session_id>"))

if ctx:
    print(f"Agent type: {ctx.agent_type}")
    print(f"Loop detected: {ctx.loop_detected}")
    print(f"Total tokens: {ctx.total_tokens:,}")
    print(f"Steps recorded: {len(ctx.steps)}")
    for step in ctx.steps:
        print(f"  Step {step.step_number}: {step.signal} | {step.token_delta} tokens | {step.description}")
```

### 3. Classify the trigger type

**No-progress loop (`no_progress` event):**
The agent completed N steps without emitting a `PROGRESS` signal. This typically means:
- The agent is stuck in a reasoning loop, re-reading the same context
- A tool call is failing silently and the agent is retrying indefinitely
- The agent's task completion condition is never satisfied

**Velocity spike (`velocity_exceeded` event):**
A single step consumed an abnormally large number of tokens. This typically means:
- The agent is appending the full conversation history on every step (context window inflation)
- A RAG retrieval returned an unexpectedly large document
- A prompt injection attack is stuffing the context window

---

## Decision Tree

```
LoopDetectedError raised
        │
        ├── Trigger: velocity_exceeded
        │         │
        │         ├── Single spike, previous steps were normal
        │         │         → Inspect the tool call result that caused the spike
        │         │         → Check for unexpected RAG retrieval size
        │         │         → Check for prompt injection in last step input
        │         │
        │         └── Velocity is consistently high across steps
        │                   → Agent is inflating context window
        │                   → Engineering fix required: implement context pruning
        │
        └── Trigger: no_progress (streak >= MAX_AGENT_STEPS)
                  │
                  ├── Steps show a repeating pattern of identical tool calls
                  │         → Agent is in a deterministic loop
                  │         → Check tool call results for silent failures (empty responses)
                  │         → Manually terminate the workflow
                  │
                  └── Steps show varied tool calls but no PROGRESS signal
                            → Agent may be making progress but not emitting signals correctly
                            → Is this a new agent? The developer may not have implemented
                              LoopSignal.PROGRESS emission (see agent-sdk-guide.md)
                            → If progress is real: manually override and resume
                            → If work is genuinely stuck: terminate and notify task owner
```

---

## Terminating a Stuck Workflow

### v0.1 (in-memory scheduler)

There is no persistent workflow to terminate. The session is already halted — `LoopDetectedError` prevents further `record_step()` calls from succeeding. Notify the task owner that the task did not complete.

```bash
# Confirm the session's final state in the logs
docker logs aegis-api --since 1h 2>&1 | grep "<session_id>" | tail -20
```

### Phase 2+ (Temporal scheduler)

Navigate to the Temporal UI → Workflows → find the `workflow_id` → click **Terminate**.

Alternatively, terminate via the Temporal CLI:

```bash
temporal workflow terminate \
  --workflow-id "<workflow_id>" \
  --reason "Loop detected — human termination after review on $(date -u)"
```

---

## Resuming a Legitimate Long-Running Task

If investigation confirms the agent was making real progress but failed to emit `PROGRESS` signals (a bug in the agent code):

1. Note the last successful step and its output from the audit log.
2. Create a new task request with the description updated to start from where the agent left off.
3. Ensure the agent developer adds `LoopSignal.PROGRESS` emission before the next deployment (see `docs/agent-sdk-guide.md`).
4. Monitor the new session closely.

---

## Post-Incident Actions

- [ ] Record an `AuditEvent` for the intervention: `action: "incident.loop_detected"`, `outcome: "success"` (resolved) or `"failure"` (unresolved), with the `session_id` in `metadata`.
- [ ] Notify the task owner of the outcome and ETA for resubmission.
- [ ] If the trigger was a token velocity spike from a known large document type, consider increasing `AEGIS_MAX_TOKEN_VELOCITY` for that `agent_type` specifically — or add context-length limiting in the adapter.
- [ ] If the trigger was no-progress on a task that genuinely needs more than 10 steps, evaluate increasing `AEGIS_MAX_AGENT_STEPS` for that task type, or refactor the agent to emit granular `PROGRESS` signals per sub-step.
- [ ] File an issue in the agent's repository linking the `task_id` and the step trace.

---

## Escalation

| Condition | Escalate To |
|---|---|
| Velocity spike accompanied by anomalous prompt content | Security Team (possible injection attack) |
| Loop pattern that systematically generates maximum token usage | Security Team + Engineering Lead |
| Multiple unrelated agents looping within 24 hours | Engineering Lead (possible systemic issue) |
| Temporal workflow cannot be terminated via UI or CLI | Temporal cluster operator |
