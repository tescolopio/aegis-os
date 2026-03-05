# Aegis-OS Policy Authoring Guide

**Audience:** Platform operators, security engineers, and policy authors managing Aegis-OS governance rules  
**Version:** 0.1.0

This guide covers how to write, test, load, and evolve Rego policies for the Aegis-OS policy engine.

---

## Table of Contents

- [Overview](#overview)
- [How Policies Are Evaluated](#how-policies-are-evaluated)
- [The `input` Document](#the-input-document)
- [Policy File Structure](#policy-file-structure)
- [Existing Policies](#existing-policies)
- [Writing a New Policy](#writing-a-new-policy)
- [Testing Policies Locally](#testing-policies-locally)
- [Loading Policies into OPA](#loading-policies-into-opa)
- [Querying OPA Directly](#querying-opa-directly)
- [Policy Versioning & Change Control](#policy-versioning--change-control)
- [Common Patterns & Recipes](#common-patterns--recipes)

---

## Overview

Aegis-OS uses [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) as its policy engine. Policies are written in **Rego**, OPA's declarative query language. All `*.rego` files in the `policies/` directory are loaded into the OPA server at container startup and evaluated at runtime by `PolicyEngine` in `src/governance/policy_engine/opa_client.py`.

A core design principle: **policy changes never require a code deployment**. Updating a `.rego` file and reloading the OPA server is sufficient to change an access decision.

---

## How Policies Are Evaluated

When `PolicyEngine.evaluate(policy_name, input_data)` is called:

1. An HTTP `POST` is sent to `{OPA_URL}/v1/data/aegis/{policy_name}` with a JSON body:
   ```json
   { "input": { "agent_type": "...", "requester_id": "...", "action": "...", "resource": "...", "metadata": {} } }
   ```
2. OPA evaluates the corresponding Rego rule and returns a `result` object.
3. The Control Plane reads `result.allow` (boolean) and `result.reasons` (list of strings).
4. If `allow` is `false`, the request is rejected and `reasons` is returned to the caller.

**Fail-closed principle:** If OPA is unreachable, the Control Plane returns HTTP 503 — it never defaults to `allow: true`.

---

## The `input` Document

The `input` document available inside every Rego policy is populated from `PolicyInput`:

```python
# src/governance/policy_engine/opa_client.py
class PolicyInput(BaseModel):
    agent_type: str          # e.g. "finance", "hr", "it", "legal", "general"
    requester_id: str        # e.g. "user:alice@corp.com"
    action: str              # e.g. "read", "write"
    resource: str            # e.g. "finance_db", "contracts"
    metadata: dict[str, str] # e.g. {"sensitive_masking": "enabled"}
```

Inside Rego, access these as:
```rego
input.agent_type
input.requester_id
input.action
input.resource
input.metadata.sensitive_masking
input.token_expired   # boolean, set by the Control Plane before evaluation
```

---

## Policy File Structure

Each file in `policies/` must declare a package under the `aegis` namespace:

```rego
package aegis.<policy_name>

import rego.v1

# Always set a safe default
default allow := false

# Rules that grant access
allow if { ... }

# Optional: human-readable denial reasons
reasons contains "reason_key" if { ... }
```

**Package naming convention:** `aegis.<snake_case_policy_name>` — matching the `policy_name` argument passed to `PolicyEngine.evaluate()`.

---

## Existing Policies

### `policies/agent_access.rego` — `aegis.agent_access`

Controls which agent types can read or write which resources.

**Key rules:**
- `agent_permissions` — a static map of `agent_type` → `{action: [resources]}`
- `allow` — granted if the `agent_type` has the requested `action` on the `resource` AND the token is not expired
- For `finance`, `hr`, and `legal` types: `metadata.sensitive_masking` must equal `"enabled"` or the request is denied with reason `pii_masking_required`

**Denial reasons:**
| Reason key | Trigger |
|---|---|
| `token_expired` | `input.token_expired == true` |
| `pii_masking_required` | Sensitive agent type without masking enabled |
| `resource_not_permitted` | Resource not in the agent type's allowlist |

### `policies/budget.rego` — `aegis.budget`

Controls budget extension approvals for agent sessions.

**Key rules:**
- `allow_budget_extension` — `finance`, `hr`, `it` agent types may extend ≤ $50 with `approver_role: "manager"`
- `deny_budget_extension` — extensions > $500 require `approver_role: "executive"`; will be denied for all others

---

## Writing a New Policy

**Example: restrict task submission to business hours only**

Create `policies/schedule.rego`:

```rego
package aegis.schedule

import rego.v1

default allow := false

# Allow only during business hours Mon-Fri 08:00-18:00 UTC
allow if {
    # time.clock returns [hour, minute, second] for the given RFC3339 timestamp
    t := time.clock(["2006-01-02T15:04:05Z07:00", input.metadata.request_time])
    t[0] >= 8
    t[0] < 18
    d := time.weekday(time.parse_rfc3339_ns(input.metadata.request_time))
    d != "Saturday"
    d != "Sunday"
}

reasons contains "outside_business_hours" if {
    not allow
}
```

Then call from Python:

```python
result = await policy_engine.evaluate(
    "schedule",
    PolicyInput(
        agent_type="general",
        requester_id="user:bob",
        action="read",
        resource="public_kb",
        metadata={"request_time": "2026-03-03T14:30:00Z"},
    )
)
```

---

## Testing Policies Locally

OPA has a built-in test runner. Write test files alongside your policies with a `_test.rego` suffix.

**Example: `policies/agent_access_test.rego`**

```rego
package aegis.agent_access_test

import rego.v1

test_finance_read_allowed if {
    allow with input as {
        "agent_type": "finance",
        "requester_id": "user:alice",
        "action": "read",
        "resource": "finance_db",
        "token_expired": false,
        "metadata": {"sensitive_masking": "enabled"},
    }
}

test_finance_denied_without_masking if {
    not allow with input as {
        "agent_type": "finance",
        "requester_id": "user:alice",
        "action": "read",
        "resource": "finance_db",
        "token_expired": false,
        "metadata": {},
    }
    reasons == {"pii_masking_required"} with input as {
        "agent_type": "finance",
        "requester_id": "user:alice",
        "action": "read",
        "resource": "finance_db",
        "token_expired": false,
        "metadata": {},
    }
}

test_expired_token_denied if {
    not allow with input as {
        "agent_type": "it",
        "requester_id": "user:bob",
        "action": "read",
        "resource": "logs",
        "token_expired": true,
        "metadata": {},
    }
}

test_general_write_denied if {
    # general agents have no write permissions
    not allow with input as {
        "agent_type": "general",
        "requester_id": "user:carol",
        "action": "write",
        "resource": "public_kb",
        "token_expired": false,
        "metadata": {},
    }
}
```

**Run all tests:**

```bash
# Using the OPA binary
opa test policies/ -v

# Using Docker (no local OPA install required)
docker run --rm -v $(pwd)/policies:/policies \
  openpolicyagent/opa:0.68.0 test /policies -v
```

All tests must pass before merging a policy change. Add policy tests to CI:

```yaml
# .github/workflows/policy-test.yml
- name: Test OPA policies
  run: |
    docker run --rm -v ${{ github.workspace }}/policies:/policies \
      openpolicyagent/opa:0.68.0 test /policies -v --exit-zero-on-skipped
```

---

## Loading Policies into OPA

**Docker (automatic on startup):**

The `docker-compose.yml` mounts `./policies` into the OPA container and runs:
```
opa run --server --addr=0.0.0.0:8181 --log-level=info /policies
```

All `*.rego` files in `policies/` are loaded automatically. Restart the OPA container to pick up changes:

```bash
docker-compose restart opa
```

**Hot reload without restart (development only):**

OPA's REST API accepts bundle pushes. For development iteration, use the OPA CLI `eval` command to test a specific rule before restarting:

```bash
echo '{"input": {"agent_type": "hr", "requester_id": "user:x", "action": "read", "resource": "hr_db", "token_expired": false, "metadata": {"sensitive_masking": "enabled"}}}' \
  | opa eval -I -d policies/agent_access.rego 'data.aegis.agent_access.allow'
```

---

## Querying OPA Directly

You can query any loaded policy directly via the OPA REST API for debugging:

```bash
# Check an access decision
curl -s -X POST http://localhost:8181/v1/data/aegis/agent_access \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "agent_type": "legal",
      "requester_id": "user:claire",
      "action": "read",
      "resource": "contracts",
      "token_expired": false,
      "metadata": {"sensitive_masking": "enabled"}
    }
  }' | jq .result
```

```json
{
  "allow": true,
  "agent_permissions": { ... },
  "reasons": []
}
```

```bash
# List all loaded policies
curl http://localhost:8181/v1/policies | jq '[.result[].id]'
```

---

## Policy Versioning & Change Control

Every policy change **must** follow this process to maintain an auditable governance history:

1. **Branch** — create a feature branch: `policy/add-schedule-enforcement`
2. **Write tests first** — add `_test.rego` cases covering both the allow and deny paths
3. **Run `opa test`** locally and confirm all tests pass
4. **Update `CHANGELOG.md`** — document the policy change under `[Unreleased]`
5. **Pull Request** — require at least one review from a security or compliance stakeholder
6. **Merge & deploy** — restart the OPA container in each environment in sequence: dev → staging → production
7. **Verify** — call the OPA `/v1/policies` endpoint in each environment to confirm the new policy version is loaded

**Policy changes that widen permissions** (relaxing a `default deny`, adding a new allowed resource, removing a `reasons` check) require two reviewers and a compliance sign-off.

---

## Common Patterns & Recipes

### Default deny with allowlist

```rego
default allow := false

allowed_requesters := {"service:ci-bot", "service:audit-runner"}

allow if {
    input.requester_id in allowed_requesters
}
```

### Time-bounded access

```rego
allow if {
    input.agent_type == "it"
    input.action == "write"
    input.resource == "tickets"
    # Only allow writes during an active maintenance window stored in metadata
    input.metadata.maintenance_window == "active"
}
```

### Combining multiple conditions with shared helper rule

```rego
token_valid if {
    not input.token_expired
}

agent_permitted if {
    token_valid
    perms := agent_permissions[input.agent_type]
    input.resource in perms[input.action]
}

allow if {
    agent_permitted
}
```

### Reading from an external data document

OPA can load supplemental data files (JSON/YAML) alongside policies. Create `policies/data.json`:

```json
{
  "approved_cost_centers": ["CC-001", "CC-017", "CC-042"]
}
```

Reference it in Rego as `data.approved_cost_centers`:

```rego
allow if {
    input.metadata.cost_center in data.approved_cost_centers
    agent_permitted
}
```
