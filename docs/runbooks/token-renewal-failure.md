# Runbook: Token Renewal Failure

**Severity:** Medium–High (depends on whether active tasks are blocked)  
**Alert source:** HTTP 400 responses with OPA reason `token_expired`; `jose.ExpiredSignatureError` in aegis-api logs; task owner reports inability to submit tasks  
**Primary on-call role:** Platform Engineer

---

## Symptoms

One or more of the following:

- API calls return HTTP 400 with `detail` containing `token_expired` or `reasons: ["token_expired"]`
- `jose.exceptions.ExpiredSignatureError` appears in aegis-api logs
- An active agent workflow is blocked: the agent cannot request a new token
- Audit log contains `policy.denied` events with `metadata.reason: "token_expired"` in high volume
- A task that was working fine begins failing after approximately 15 minutes

---

## Background: JIT Token Lifecycle

Aegis-OS issues HS256-signed JWTs with a 15-minute expiry (`AEGIS_TOKEN_EXPIRY_SECONDS`, default `900`). Tokens carry:

- `jti` — unique ID for the token (used for audit correlation)
- `sub` — the `requester_id` of the caller
- `agent_type` — the scope of the token
- `exp` — Unix timestamp of expiry

Tokens are validated by OPA via the `input.token_expired` field set by the Control Plane before calling `PolicyEngine.evaluate()`. An expired token always results in `allow: false` with reason `token_expired`.

**Tokens are not refreshed automatically.** Agents and integrations must proactively detect approaching expiry and re-submit a task request to obtain a new token.

---

## Immediate Triage (< 5 minutes)

### 1. Confirm the failure is a token expiry issue

```bash
# Search logs for token expiry events
docker logs aegis-api --since 1h 2>&1 | grep -E "token_expired|ExpiredSignatureError"
```

### 2. Check the current system time on the API host

Token expiry is time-based. Clock skew between the token issuer and validator causes premature or delayed expiry.

```bash
# Check host time
date -u

# Check time inside the container
docker-compose exec aegis-api date -u

# Compare — if they differ by more than a few seconds, you have a clock skew issue
```

### 3. Inspect the failing token

If you have the bearer token from the failing request, inspect its claims (no signature verification needed to read claims):

```bash
# Decode the JWT payload (base64 decode the middle segment)
echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Key fields to check:
# "exp": Unix timestamp → compare to current time
# "agent_type": must match the resource being accessed
# "iat": issued-at → verify this is recent
```

### 4. Verify the signing key is consistent

If tokens were valid yesterday but are failing today across all requests, the signing key may have been rotated without issuing new tokens:

```bash
# Check when AEGIS_TOKEN_SECRET_KEY was last changed
docker-compose exec aegis-api env | grep AEGIS_TOKEN_SECRET_KEY
# (do not log or share the key value)

# Verify by issuing a fresh token and attempting to validate it
curl -s -X POST http://localhost:8000/api/v1/tasks \
  -H "Content-Type: application/json" \
  -d '{"description":"token test","agent_type":"general","requester_id":"user:ops"}' \
  | jq .session_token
# If this succeeds, new tokens are working; old tokens issued before the key rotation are invalid
```

---

## Resolution Procedures

### Scenario A: Token expired naturally (expected behavior)

The agent or integration did not renew the token before the 15-minute window expired. This is the most common case and is expected behavior — not an incident.

**Resolution:** Have the agent resubmit a `POST /api/v1/tasks` request to obtain a fresh token.

**Prevention:** Implement proactive renewal in the agent integration (see `docs/agent-sdk-guide.md`):

```python
import time
from jose import jwt as jose_jwt

def should_renew(token: str, buffer_seconds: int = 60) -> bool:
    claims = jose_jwt.get_unverified_claims(token)
    return time.time() > claims["exp"] - buffer_seconds

# In the agent loop:
if should_renew(current_token):
    current_token = obtain_new_token()
```

Consider reducing `AEGIS_TOKEN_EXPIRY_SECONDS` for high-security contexts (e.g., 5 minutes for `finance`) and increasing it for known long-running batch tasks.

### Scenario B: Clock skew between services

If the time difference between the token issuer (aegis-api) and the validator (OPA or aegis-api itself) is more than a few seconds, tokens may appear expired before they actually are.

```bash
# Fix NTP synchronization on the host
sudo timedatectl set-ntp true
sudo systemctl restart systemd-timesyncd

# Verify
timedatectl status
# "synchronized: yes" should appear

# Restart aegis-api to re-sync
docker-compose restart aegis-api
```

For Kubernetes deployments, clock skew is typically a node-level issue:

```bash
kubectl get nodes -o wide
# If nodes are out of sync, contact your cloud provider or cluster admin
```

### Scenario C: Signing key rotated without re-issuance

All tokens issued before a key rotation are permanently invalid. This is **expected and intentional** — rotating the key invalidates all outstanding sessions.

If the rotation was unintentional (accidental key change):

1. Revert `AEGIS_TOKEN_SECRET_KEY` to the previous value in the environment.
2. Restart aegis-api.
3. Verify existing tokens are accepted again.

If the rotation was intentional:

1. Notify all active agents that their session tokens are no longer valid.
2. Have all agents resubmit their task requests to obtain new tokens.
3. Update `CHANGELOG.md` noting the rotation date.

### Scenario D: `token_expiry_seconds` was reduced in configuration

If `AEGIS_TOKEN_EXPIRY_SECONDS` was recently decreased, active agents with tokens issued under the old value may see them expire sooner than expected.

```bash
# Check current configured expiry
docker-compose exec aegis-api env | grep AEGIS_TOKEN_EXPIRY_SECONDS
```

If the new value is correct, agents simply need to renew more frequently. Update the affected integrations.

### Scenario E: `jose` library validation error (not a clock or key issue)

If `jose.exceptions.JWTError` appears for reasons other than expiry (e.g., `Signature verification failed`, `Not enough segments`):

```bash
# Check for corrupted or truncated tokens in the request logs
docker logs aegis-api --since 1h 2>&1 | grep "JWTError"
```

This can occur due to:
- Token being truncated in HTTP headers (rare; check proxy header size limits)
- Token being URL-encoded where Base64 padding `=` characters are mishandled

Verify the Authorization header is being passed as `Bearer <token>` without URL encoding.

---

## Post-Incident Actions

- [ ] If agents were blocked, confirm they have successfully renewed tokens and resumed work.
- [ ] Record an `AuditEvent` if the expiry caused a significant task disruption: `action: "incident.token_renewal_failure"`, `outcome: "success"` once resolved.
- [ ] If caused by a missing renewal implementation in an agent: file a defect with the agent team and link to `docs/agent-sdk-guide.md#token-renewal`.
- [ ] If caused by clock skew: verify NTP is configured and active on all nodes; add a clock skew Prometheus alert.
- [ ] If caused by an accidental key rotation: add a change management step requiring dual approval before rotating `AEGIS_TOKEN_SECRET_KEY` in any environment.

---

## Escalation

| Condition | Escalate To |
|---|---|
| All agents across all task types failing simultaneously | Engineering Lead — possible signing key corruption or service misconfiguration |
| Clock skew > 30 seconds between containers | Infrastructure team |
| Token failures occurring before 15-minute expiry with correct system time | Engineering Lead (possible `python-jose` version regression) |
| Evidence of token reuse or replay attacks (same `jti` seen twice) | Security Team immediately |
