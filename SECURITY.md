# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x (current) | ✅ Active development |

Aegis-OS is pre-v1.0. Security fixes are applied to the `main` branch immediately and released as patch versions. There are no LTS branches at this stage.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub Issues.**

Email: **security@3dtechsolutions.io**

Include in your report:
- A description of the vulnerability and the component affected
- Steps to reproduce (proof-of-concept code or curl commands are appreciated)
- The potential impact and attack scenario
- Whether you believe the issue is already being exploited in the wild

You will receive an acknowledgment within **48 hours** and a full response with an action plan within **7 business days**. If the issue is confirmed, a CVE will be requested and you will be credited in the changelog unless you request otherwise.

---

## Pre-Production Security Checklist

Aegis-OS ships with development defaults that are **intentionally insecure**. Before deploying in any non-local environment, complete every item below.

### Authentication & Secrets

- [ ] **Replace `AEGIS_TOKEN_SECRET_KEY`** with a cryptographically random value of at least 256 bits.
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- [ ] **Rotate Vault root token.** The default `aegis-dev-root-token` is publicly known. Initialize Vault in production mode with proper unseal keys and create a scoped AppRole for Aegis-OS.
- [ ] **Never set `AEGIS_VAULT_TOKEN` to the Vault root token** in production. Create a least-privilege Vault policy and AppRole.
- [ ] **Provision LLM provider API keys through Vault** (HashiCorp Vault Dynamic Secrets or KV-v2), not environment variables.
- [ ] **Enable Vault audit logging** to capture every secrets access.

### Network & Transport

- [ ] **Enforce TLS 1.3** on all external-facing endpoints (`/api/v1/*`, `/health`, `/metrics`).
- [ ] **Restrict `/metrics`** to inbound connections from the Prometheus scrape IP only. This endpoint exposes operational data (token velocity, budget remaining) that could aid an attacker.
- [ ] **Firewall ports 8181 (OPA), 8200 (Vault), 7233 (Temporal), and 5432 (PostgreSQL)** from external access. These services should be accessible only within the container network.
- [ ] **Enable mTLS** between the Control Plane and OPA, Vault, and Temporal (target: Phase 4).

### OPA & Policy Enforcement

- [ ] **Sign OPA bundles** before loading into the OPA server. Use `opa build` with `--signing-key` to produce a signed bundle. Configure the OPA server to verify signatures on load.
- [ ] **Verify OPA fails closed.** Test by stopping the OPA container; confirm the Control Plane returns HTTP 503, not HTTP 200 with a permissive response.
- [ ] **Review `policies/agent_access.rego`** and remove any permissions not required by your deployed agent types. The principle of least privilege applies to Rego rules.

### Guardrails

- [ ] **Audit the PII pattern library** (`src/governance/guardrails.py`) for coverage of data types relevant to your organization (e.g., UK National Insurance numbers, EU IBAN formats).
- [ ] **Test injection detection** using the OWASP LLM Top 10 test vectors before go-live.
- [ ] **Confirm post-response sanitization is enabled** end-to-end — not just on inbound prompts.

### Audit & Observability

- [ ] **Replace the `ConsoleSpanExporter`** in `AuditLogger` with an OTLP exporter pointing to your production collector. Console output is not durable.
- [ ] **Configure log aggregation** (ELK, Splunk, or Grafana Loki) to receive and retain Aegis structured logs with a retention period meeting your compliance requirements (90 days minimum for SOC2).
- [ ] **Set Prometheus alerting rules** for: policy violation spike, high token velocity, budget exhaustion rate, OPA error rate.

### Container & Runtime

- [ ] **Remove the Vault `server -dev` command** from `docker-compose.yml` and replace with a production Vault configuration.
- [ ] **Pin all container image digests** in `docker-compose.yml` (replace `image: tag` with `image: name@sha256:...`).
- [ ] **Run the Aegis API container as a non-root user.** Add `user: "1000:1000"` to the `aegis-api` service in `docker-compose.yml`.
- [ ] **Set `read_only: true`** on the `aegis-api` container filesystem where possible; mount only required volumes.

---

## Known Limitations (v0.1.0)

These are **accepted risks** in the current development build. They are **not acceptable** in production.

| Limitation | Impact | Resolution |
|---|---|---|
| No API authentication on `/api/v1/tasks` | Any network-reachable client can submit tasks | Deploy behind an authenticated API gateway (Phase 1) |
| In-memory session state | Process restart loses all budget and loop tracking | Temporal durable state (Phase 2) |
| Vault in dev mode | Static root token, no seal, no audit log | Production Vault config (Phase 4) |
| JWT signing key in environment | Key exposed via process env or `docker inspect` | Vault Transit Secrets Engine (Phase 4) |
| Stdout-only audit log | Logs are not persisted or tamper-evident | Write-once log store — Immudb or QLDB (Phase 3) |
| No inter-service mTLS | Service impersonation within the container network possible | mTLS with SPIFFE/SPIRE (Phase 4) |
| OPA partially fail-closed | Connection errors raise a Python exception but do not guarantee 503 to the caller | Explicit fail-closed middleware (Phase 1) |

---

## Security-Relevant Dependencies

The following dependencies have direct security impact and should be monitored for CVEs:

| Package | Role | Monitor Via |
|---|---|---|
| `python-jose[cryptography]` | JWT signing/verification | [PyPA Advisory DB](https://github.com/pypa/advisory-database) |
| `cryptography` | Underlying crypto primitives | [PyPA Advisory DB](https://github.com/pypa/advisory-database) |
| `fastapi` | HTTP attack surface (header injection, path traversal) | [PyPA Advisory DB](https://github.com/pypa/advisory-database) |
| `httpx` | SSRF risk in OPA client | [PyPA Advisory DB](https://github.com/pypa/advisory-database) |
| `openpolicyagent/opa` | Policy engine | [OPA security advisories](https://github.com/open-policy-agent/opa/security/advisories) |
| `hashicorp/vault` | Secrets management | [Vault changelog](https://github.com/hashicorp/vault/blob/main/CHANGELOG.md) |

Run `pip audit` in CI to catch known vulnerabilities in Python dependencies automatically.
