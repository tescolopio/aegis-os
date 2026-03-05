# Aegis-OS Compliance Guide

**Audience:** Compliance officers, auditors, and security engineers  
**Version:** 0.1.0  
**Frameworks:** SOC2 Type II, GDPR

This guide explains how to use the Aegis-OS Audit Vault to generate and interpret compliance reports, what audit events map to which controls, and the evidence artifacts produced for each framework.

---

## Table of Contents

- [Overview](#overview)
- [Audit Event Model](#audit-event-model)
- [Generating a Compliance Report](#generating-a-compliance-report)
- [SOC2 Type II Mapping](#soc2-type-ii-mapping)
- [GDPR Mapping](#gdpr-mapping)
- [Evidence Artifacts](#evidence-artifacts)
- [Continuous Control Monitoring](#continuous-control-monitoring)
- [Retention Requirements](#retention-requirements)
- [Limitations & Roadmap](#limitations--roadmap)

---

## Overview

Every action taken by an AI agent under Aegis-OS produces an immutable audit event. These events are the foundation of all compliance reporting. The `ComplianceReporter` class in `src/audit_vault/compliance.py` aggregates events for any time window and produces structured reports aligned to either the SOC2 or GDPR framework.

Compliance reports are **not** a substitute for a full audit by a qualified assessor. They are **machine-generated evidence artifacts** — the raw material that an assessor uses to verify that controls were operating during the audit period.

---

## Audit Event Model

Every audit event is an immutable `AuditEvent` record:

```python
class AuditEvent(BaseModel):
    event_id: UUID          # Unique identifier for this event
    timestamp: datetime     # UTC timestamp of the event
    agent_id: str           # Identity of the agent that performed the action
    action: str             # What was done (e.g., "task.submitted", "policy.evaluated")
    resource: str           # What was acted upon (e.g., "finance_db", "pii.email")
    outcome: str            # "success" or "failure"
    metadata: dict[str, str]  # Additional context (task_id, agent_type, reasons, etc.)
```

### Standard Event Taxonomy

The following event names are emitted by Aegis-OS core modules. Downstream agents should follow the same naming convention (`component.action`):

| Event Name | Source Module | Description |
|---|---|---|
| `aegis.startup` | `main.py` | Control Plane started |
| `aegis.shutdown` | `main.py` | Control Plane stopped |
| `task.routing` | `router.py` | Incoming task received |
| `task.routed` | `router.py` | Task routed, token issued |
| `budget.session_created` | `budget_enforcer.py` | New budget session opened |
| `budget.exceeded` | `budget_enforcer.py` | Session exceeded USD budget (critical) |
| `loop_detector.context_created` | `loop_detector.py` | Loop tracking context opened |
| `loop_detector.velocity_exceeded` | `loop_detector.py` | Token velocity spike detected (critical) |
| `loop_detector.no_progress` | `loop_detector.py` | No-progress circuit breaker triggered (critical) |
| `workflow.scheduled` | `scheduler.py` | Agent workflow scheduled |
| `policy.evaluated` | `opa_client.py` | OPA policy decision made |
| `policy.denied` | `opa_client.py` | OPA returned `allow: false` |

Events with outcome `"failure"` or emitted with `_logger.warning()` / `_logger.error()` are flagged as findings in SOC2 reports.

---

## Generating a Compliance Report

```python
from datetime import datetime, timezone
from src.audit_vault.compliance import (
    ComplianceReporter,
    ComplianceFramework,
    AuditEvent,
)

reporter = ComplianceReporter()

# In production, events are loaded from the persistent audit store.
# In v0.1, they are recorded in-memory during the process lifetime.
reporter.record_event(AuditEvent(
    agent_id="service:contract-review-bot",
    action="task.routing",
    resource="contracts",
    outcome="success",
    metadata={"task_id": "abc123", "agent_type": "legal"},
))

# Generate a SOC2 report for a specific 24-hour period
period_start = datetime(2026, 3, 3, 0, 0, 0, tzinfo=timezone.utc)
period_end   = datetime(2026, 3, 3, 23, 59, 59, tzinfo=timezone.utc)

report = reporter.generate_report(
    framework=ComplianceFramework.SOC2,
    period_start=period_start,
    period_end=period_end,
)

print(report.model_dump_json(indent=2))
```

### Report Structure

```json
{
  "report_id": "7f3a...",
  "framework": "SOC2",
  "generated_at": "2026-03-03T23:59:59Z",
  "period_start": "2026-03-03T00:00:00Z",
  "period_end": "2026-03-03T23:59:59Z",
  "total_events": 142,
  "events": [ ... ],
  "summary": "SOC2 Audit Summary: 142 total events, 3 failures recorded."
}
```

---

## SOC2 Type II Mapping

SOC2 evaluates controls against the AICPA Trust Services Criteria (TSC). The following table maps Aegis-OS controls to the relevant criteria.

### CC6 — Logical and Physical Access Controls

| Criteria | Aegis-OS Control | Evidence |
|---|---|---|
| CC6.1 — Restrict logical access | JIT session tokens scoped to `agent_type` | `task.routed` events with `session_token` issuance; `TokenClaims` logged with `agent_type` and `exp` |
| CC6.2 — Authenticate users | All task requests require a valid JWT for resource access | `policy.denied` events with `reason: token_expired` show expired tokens are rejected |
| CC6.3 — Remove access | 15-minute token expiry | Every `TokenClaims.expires_at` in the audit log; no long-lived credentials |
| CC6.6 — Monitor and review access | OPA evaluates every access request | `policy.evaluated` event for every agent action with `allowed` boolean logged |
| CC6.7 — Prevent unauthorized access | Default-deny OPA policies | `policy.denied` events with `reason: resource_not_permitted`; no `allow: true` without explicit match |

### CC7 — System Operations

| Criteria | Aegis-OS Control | Evidence |
|---|---|---|
| CC7.2 — Monitor for threats | `LoopDetector` and `BudgetEnforcer` monitor for anomalous behavior | `loop_detector.no_progress` and `budget.exceeded` warning events |
| CC7.4 — Respond to identified incidents | `WorkflowStatus.HUMAN_INTERVENTION_REQUIRED` triggers human review | `loop_detector.velocity_exceeded` events with `intervention_required: true` |

### CC8 — Change Management

| Criteria | Aegis-OS Control | Evidence |
|---|---|---|
| CC8.1 — Authorize changes | Policy changes require PR review + OPA test passing | Git history of `policies/` directory; CI test results |

### CC9 — Risk Mitigation

| Criteria | Aegis-OS Control | Evidence |
|---|---|---|
| CC9.2 — Monitor vendor risk | `BudgetEnforcer` tracks spend per LLM provider session | `aegis_tokens_consumed_total` Prometheus metric; `BudgetSession.agent_type` in events |

### PI1 — Processing Integrity

| Criteria | Aegis-OS Control | Evidence |
|---|---|---|
| PI1.1 — Complete and accurate processing | Every `task_id` links prompt, guardrail result, policy decision, and response in audit log | Correlated events sharing `task_id` in `metadata` |
| PI1.2 — Processing is authorized | OPA deny-by-default | `policy.evaluated` events for 100% of task requests |

### P Series — Privacy (if applicable)

| Criteria | Aegis-OS Control | Evidence |
|---|---|---|
| P3.1 — Collect only necessary data | PII redacted before LLM submission | `task.routed` events show `pii_found` types; sanitized prompt in metadata |
| P6.1 — Disclose personal data only as permitted | PII masked in all outbound LLM calls and responses | `Guardrails.mask_pii()` result logged; post-response sanitization events |

### SOC2 Report Summary Interpretation

The `summary` field in a SOC2 report reads:

```
SOC2 Audit Summary: 142 total events, 3 failures recorded.
```

**`total_events`** — all `AuditEvent` records within the period. A healthy system will show a ratio of failures to total events well below 1%.

**`failures recorded`** — events where `outcome == "failure"`. An assessor will review each failure to confirm it was detected, logged, and responded to appropriately. Unreviewed failures are a finding.

---

## GDPR Mapping

GDPR compliance for AI systems principally concerns **Articles 5, 13/14, 17, 22, and 30**.

### Article 5 — Principles of Processing

| Principle | Aegis-OS Control |
|---|---|
| Lawfulness, fairness, transparency | Every agent action is logged; `requester_id` links actions to an identifiable principal |
| Purpose limitation | `agent_type` scoping (e.g., `hr` can only access `hr_db`) enforces purpose limitation at the infrastructure layer |
| Data minimisation | PII masking removes unnecessary personal data before it reaches the LLM |
| Accuracy | Post-response guardrail prevents inaccurate (hallucinated) PII from entering outputs |
| Storage limitation | Audit events must be purged after the retention period; see [Retention Requirements](#retention-requirements) |
| Integrity and confidentiality | Audit logs are append-only (Phase 3); token signing ensures integrity; Vault encrypts secrets |

### Article 17 — Right to Erasure

**The tension:** An immutable audit log conflicts with the right to erasure of personal data.

**Aegis-OS resolution (Phase 3):** All audit events containing personal data will be encrypted with a per-data-subject key stored in Vault. Erasure is implemented by destroying the Vault key — the ciphertext remains but is permanently unreadable. This satisfies GDPR Article 17 without breaking audit chain integrity.

Until Phase 3, operators must:
1. Identify all `AuditEvent` records containing personal data for a subject using the `agent_id` or `metadata` fields.
2. Redact them in the audit store before responding to an erasure request.
3. Document the redaction in the compliance report metadata.

### Article 22 — Automated Decision-Making

If Aegis-OS's OPA policy decisions constitute "solely automated" decisions with "significant effect" on data subjects, Article 22 applies. In most enterprise deployments, the agent is making decisions *on behalf of* a human operator, not about the data subject directly. Document this distinction in your Record of Processing Activities (RoPA).

### Article 30 — Records of Processing Activities

The GDPR compliance report generated by `ComplianceReporter` contributes to your Article 30 RoPA. The report summary field for GDPR reads:

```
GDPR Audit Summary: 142 total events, 8 PII-related access events.
```

**`PII-related access events`** — events where `resource` contains `"pii"` (case-insensitive). Use this count to populate the "categories of personal data" and "processing activity" fields in your RoPA.

### GDPR Compliance Report Usage

```python
gdpr_report = reporter.generate_report(
    framework=ComplianceFramework.GDPR,
    period_start=period_start,
    period_end=period_end,
)
# gdpr_report.summary:
# "GDPR Audit Summary: 142 total events, 8 PII-related access events."

# Filter for PII events only:
pii_events = [e for e in gdpr_report.events if "pii" in e.resource.lower()]
```

---

## Evidence Artifacts

For each compliance audit period, produce the following artifacts:

| Artifact | Source | Format |
|---|---|---|
| Compliance report (JSON) | `ComplianceReporter.generate_report()` | JSON |
| Prometheus metrics snapshot | `GET /metrics` at period end | Prometheus text |
| OPA policy archive | Git tag of `policies/` at period start and end | `.tar.gz` |
| Token issuance log | `task.routed` events filtered from audit log | JSON lines |
| Policy denial log | `policy.denied` events | JSON lines |
| Watchdog event log | `budget.exceeded` + `loop_detector.*` events | JSON lines |
| Test results | CI run for the release deployed during the period | JUnit XML |

Store these artifacts in an access-controlled, write-once store (S3 Object Lock, Google Cloud Storage with retention policies, or QLDB in Phase 3).

---

## Continuous Control Monitoring

Rather than waiting until an audit to discover failures, implement the following automated control tests that run on a schedule and produce machine-readable pass/fail evidence:

| Control Test | Frequency | Implementation |
|---|---|---|
| PII masking active | Every 5 minutes | Submit a synthetic task with a known SSN pattern; verify audit log shows `[REDACTED-SSN]` within 500ms |
| OPA fail-closed | Daily | Stop OPA container; verify API returns HTTP 503; restart OPA |
| Token expiry enforced | Hourly | Submit an expired token; verify OPA returns `reasons: ["token_expired"]` |
| Budget limit enforced | Daily | Create a budget session; record tokens until `BudgetExceededError`; verify spend matches limit |
| Loop detection active | Daily | Record 10 consecutive `NO_PROGRESS` steps; verify `LoopDetectedError` is raised |

Log each test result as an `AuditEvent` with `agent_id: "control-monitor"` and `outcome: "success"` or `"failure"`.

---

## Retention Requirements

| Framework | Minimum Retention |
|---|---|
| SOC2 Type II | 12 months (for the audit period under review) |
| GDPR | Duration of processing + applicable limitation period (typically 3 years for EU data); personal data must be purged after its purpose is fulfilled |
| Internal security | 90 days minimum for incident response capability |

Configure your log aggregator retention policy accordingly. For GDPR: audit events that contain personal data in `metadata` must be subject to automated purge or key-destruction after the retention period.

---

## Limitations & Roadmap

| Limitation | Current State | Target |
|---|---|---|
| Audit store is in-memory | Events are lost on process restart | Write-once persistent store (Immudb or QLDB) — Phase 3 |
| Reports are generated from a Python list | No query API; no time-range indexing | Database-backed `ComplianceReporter` with indexed timestamps — Phase 3 |
| No automated report delivery | Reports must be generated manually | Scheduled report generation + email/S3 delivery — Phase 3 |
| No Article 17 key-destruction | Erasure requires manual redaction | Per-subject encryption via Vault Transit — Phase 3 |
| PII event detection is resource-name-based | Relies on `"pii"` appearing in the `resource` field | Structured PII event taxonomy with `event_class: "pii_access"` field — Phase 1 |
