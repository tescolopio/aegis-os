# Runbook: OPA Server Down / Policy Enforcement Degraded

**Severity:** Critical  
**Alert source:** `OPAHighErrorRate` Prometheus alert; HTTP 503 responses from `/api/v1/tasks`; `httpx.ConnectError` in aegis-api logs  
**Primary on-call role:** Platform Engineer  
**SLO Impact:** All task routing is blocked when OPA is unreachable (fail-closed design)

---

## Symptoms

One or more of the following:

- `POST /api/v1/tasks` returns HTTP 503
- Prometheus alert `OPAHighErrorRate` fires
- Aegis API logs contain `httpx.ConnectError` or `httpx.TimeoutException` pointing to the OPA URL
- Grafana shows a sudden drop to zero on the `policy.evaluated` event rate
- All task submissions fail simultaneously

---

## Background: Fail-Closed Behavior

Aegis-OS is designed to **fail closed** when OPA is unreachable. A connectivity failure to OPA must never result in an `allow: true` decision. When `PolicyEngine.evaluate()` receives an `httpx` network error, it must propagate that error as an HTTP 503 to the caller rather than defaulting to permissive behavior.

**Verify fail-closed is working:**
```bash
# Stop OPA and confirm the API returns 503 (not 200)
docker-compose stop opa
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8000/api/v1/tasks \
  -H "Content-Type: application/json" \
  -d '{"description":"test","agent_type":"general","requester_id":"user:test"}'
# Expected: 503
# If you see 200, the fail-closed behavior is NOT working — escalate immediately
docker-compose start opa
```

---

## Immediate Triage (< 5 minutes)

### 1. Check OPA container status

```bash
docker-compose ps opa
# Healthy: Up X minutes
# Unhealthy: Exit 1, Restarting, or absent
```

```bash
# Check OPA logs for startup errors or policy load failures
docker-compose logs opa --tail 50
```

Common OPA startup failures and their causes:

| Log message | Cause |
|---|---|
| `parse error` | Syntax error in a `.rego` file in `policies/` |
| `permission denied` | Policy files not readable by the OPA process |
| `address already in use` | Port 8181 conflict with another process |
| `bundle load failed` | (Production) Bundle signing verification failed |

### 2. Verify OPA health endpoint

```bash
curl -s http://localhost:8181/health | jq .
# Expected: {"status": "ok"}
# If no response: OPA is down
```

### 3. Check network connectivity from the Aegis API container

```bash
docker-compose exec aegis-api curl -s http://opa:8181/health
# If this fails but the previous command succeeds: Docker network issue
```

---

## Recovery Procedures

### Scenario A: OPA container crashed (most common)

```bash
# Restart OPA
docker-compose restart opa

# Verify it comes back healthy
sleep 5
curl -s http://localhost:8181/health
docker-compose logs opa --tail 20
```

If the container exits immediately after restart, a policy file has a syntax error:

```bash
# Test policies locally before loading
docker run --rm -v $(pwd)/policies:/policies \
  openpolicyagent/opa:0.68.0 check /policies/

# Fix any reported syntax errors, then restart
docker-compose restart opa
```

### Scenario B: Port conflict (8181 in use)

```bash
# Find what is using port 8181
lsof -i :8181  # Linux/macOS
netstat -tulpn | grep 8181  # Linux

# Stop the conflicting process, then restart OPA
docker-compose restart opa
```

### Scenario C: Docker network partition

```bash
# Recreate the Docker network
docker-compose down
docker-compose up -d

# Verify all services are on the same network
docker network inspect aegis-os_default
```

### Scenario D: Kubernetes — OPA Pod not running

```bash
# Check OPA pod status
kubectl get pods -n aegis-system -l app=opa

# Describe the pod for events
kubectl describe pod -n aegis-system <opa-pod-name>

# Restart the deployment
kubectl rollout restart deployment/opa -n aegis-system

# Follow the rollout
kubectl rollout status deployment/opa -n aegis-system
```

### Scenario E: Policy bundle verification failure (Production)

```bash
# Check OPA logs for signing errors
kubectl logs -n aegis-system deployment/opa | grep -i "bundle\|sign\|verify"

# If the signing key was rotated without updating the OPA config:
# 1. Update the OPA bundle verification key in the OPA ConfigMap
# 2. Rebuild and re-sign the bundle with the new key
# 3. Rolling restart OPA
opa build policies/ --signing-key ./new-signing-key.pem -o bundle.tar.gz
# Upload bundle.tar.gz to your bundle server
kubectl rollout restart deployment/opa -n aegis-system
```

---

## Verifying Full Recovery

After OPA is healthy, confirm the Aegis API has resumed normal policy evaluation:

```bash
# Submit a test task — should return 200 with a session token
curl -s -X POST http://localhost:8000/api/v1/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "description": "OPA recovery verification test",
    "agent_type": "general",
    "requester_id": "user:ops-verify"
  }' | jq .agent_type
# Expected: "general"

# Check audit logs for policy.evaluated events resuming
docker-compose logs aegis-api --since 2m 2>&1 | grep "policy.evaluated"
```

---

## Communication During Outage

While OPA is down, all task submissions are blocked (fail-closed). Communicate to affected teams:

- **Scope:** All agent task routing is unavailable.
- **Impact:** No new agent sessions can be started. In-flight tasks that have already received session tokens may continue if they do not require additional OPA evaluations within their 15-minute window.
- **ETA:** Provide a restoration estimate based on the scenario above.

---

## Post-Incident Actions

- [ ] Document the root cause, duration, and resolution in the incident log.
- [ ] Record an `AuditEvent`: `action: "incident.opa_outage"`, `outcome: "success"` once resolved, with `duration_seconds` in metadata.
- [ ] If caused by a bad policy deployment: ensure `opa check` is now a required step in CI before merging `.rego` changes.
- [ ] Review whether any automated retry logic in upstream callers caused unexpected behavior (e.g., duplicate task submissions) during the 503 period.
- [ ] Confirm Prometheus `OPAHighErrorRate` alert fired within 1 minute of the outage; if not, tune the alert's `for` duration.
- [ ] For Kubernetes deployments: verify OPA `readinessProbe` is configured to prevent traffic routing to unready pods.

---

## Escalation

| Condition | Escalate To |
|---|---|
| OPA is healthy but Aegis API still returns 503 | Engineering Lead (application bug — fail-closed not releasing) |
| OPA repeatedly crashes with no policy errors | Infrastructure / Container platform team |
| Bundle verification fails after key rotation | Security team + Platform Engineering |
| Outage exceeds 15 minutes during business hours | Engineering Lead + notify affected department leads |
