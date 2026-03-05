# GitHub Copilot Instructions — Aegis-OS

## What is Aegis-OS?

Aegis-OS is an **open governance runtime for enterprise AI agents**. It treats
AI agents as managed processes with strict, auditable boundaries. As
organisations move from experimental chatbots to production-scale agentic
workflows, the critical bottlenecks are no longer model performance — they are
**security**, **observability**, and **cost control**.

Every agent interaction passes through the **Aegis Governance Loop** — a
closed-loop pipeline of PII scrubbing, policy enforcement, JIT identity, real-
time economic controls, and immutable audit capture — before and after any
prompt reaches a model:

```
[Raw Prompt] → PII Scrub → Injection Check → OPA Policy → LLM Adapter → Post-Sanitize → [Clean Output]
```

The Aegis Governance Loop is the **open standard**. The enterprise runtime is
the product. This is an open-core model: the governance pipeline is a named,
versioned, publicly documented interface; the managed control plane (multi-
tenancy, compliance SLAs, managed policy packs) is the commercial layer.

---

## Project Goals

1. **Security by default.** Every agent task receives a JIT-scoped session
   token (HS256, 15-minute TTL, unique `jti`). Long-lived API keys are not
   permitted in production paths.

2. **Zero PII leakage.** All five PII classes (email, SSN, credit card, phone,
   IPv4) are scrubbed from prompts before leaving the control plane, and from
   LLM responses before returning to callers. Adversarial inputs and Unicode
   homoglyph variants must also be caught.

3. **Real-time cost control.** `BudgetEnforcer` raises `BudgetExceededError`
   synchronously within the same call frame — never deferred. Agent sessions
   may not overspend their cap by even one cent.

4. **Durable, observable orchestration.** Agent tasks must survive process
   restarts, provider outages, and rate limits without data loss or duplicate
   spend. Temporal.io is the orchestration layer.

5. **Immutable audit trail.** Every stage outcome, lifecycle transition, and
   policy decision is emitted as a structured JSON event validated against
   `docs/audit-event-schema.json`. Audit events are written to a tamper-
   evident, append-only backend.

6. **Open standard.** The Aegis Governance Loop, audit event schema, and Rego
   policy library are published, versioned, and consumable by external
   runtimes. External teams must be able to integrate against the Loop without
   a commercial licence.

---

## Architecture Overview

| Layer | Module | Primary files |
|---|---|---|
| **API & Routing** | FastAPI router | `src/control_plane/router.py` |
| **Orchestration** | Orchestrator + Temporal scheduler | `src/control_plane/orchestrator.py`, `src/control_plane/scheduler.py` |
| **LLM Adapters** | Provider-agnostic adapters | `src/adapters/` |
| **Guardrails** | PII scrub + injection detection | `src/governance/guardrails.py` |
| **Policy Engine** | OPA client + Rego policies | `src/governance/policy_engine/`, `policies/` |
| **Identity** | JIT session token management | `src/governance/session_mgr.py` |
| **Watchdog** | Budget enforcement + loop detection | `src/watchdog/` |
| **Audit** | Structured logging + OTel spans | `src/audit_vault/` |

The **router never calls governance modules directly**. All requests are
delegated to the orchestrator, which sequences the five stages in strict order.
Any direct governance import in the router is a failing test condition.

---

## Team Tracks

| Team | Owns |
|---|---|
| **Platform** | Router, orchestrator, Temporal workflow, LLM adapters |
| **Security & Governance** | Guardrails, OPA policies, JIT tokens, Vault integration |
| **Watchdog & Reliability** | BudgetEnforcer, LoopDetector, Prometheus metrics |
| **Audit & Compliance** | AuditLogger, OTel spans, ComplianceReporter |
| **Frontend & DevEx** | React console, policy editor UI, Grafana dashboards, open standard docs |

---

## Versioning and Release Gates

The project versioning follows a gate-driven release model documented in
`docs/roadmap.md`. No phase begins until the prior Go/No-Go Gate passes.

| Version | Gate | Phase |
|---|---|---|
| `v0.1.0` | — | Current prototype |
| `v0.2.0` | Gate 1 | Governance Loop Integration |
| `v0.4.0` | Gate 2 | Durable Orchestration |
| `v0.6.0` | Gate 3 | Glass Box Control Plane |
| `v0.8.0` | Gate 4 | Zero-Trust & MCP Mesh |
| `v1.0.0` | Gate 5 | Release Hardening |

---

## Industry Best Practices — Non-Negotiable Baseline

**All code, tooling, and documentation decisions must treat industry best
practices as the floor, not the ceiling.** The following are hard requirements,
not suggestions:

### Code Quality
- `mypy src/` must report **zero errors** at all times. Strict mode is
  enforced in `pyproject.toml` (`strict = true`). Type annotations are not
  optional.
- `ruff check src/ tests/` must report **zero errors**. Line length is 100.
  `ruff` replaces `flake8`, `isort`, `pyupgrade`, and `bandit` for style and
  lint. Do not introduce additional linting tools.
- No `TODO`, `FIXME`, `pass`, `raise NotImplementedError`, or `...` in any
  production code path under `src/`. Stubs and placeholders are allowed in
  test harness anchors only, and must raise `NotImplementedError` loudly so
  accidental invocation fails immediately.
- All public functions, classes, and methods must have complete, accurate
  docstrings. Incomplete docstrings block the documentation release requirement.

### Testing
- Tests must assert **behaviour**, not implementation details. Mock at the
  boundary (adapter, OPA, Temporal), not in the middle of business logic.
- Every new production code path must be covered by at least one unit test
  and one integration test before a gate review.
- No test may use `xfail`, `skip`, or feature-flag guards to achieve a
  passing CI run. If a feature is incomplete, the test fails loudly.
- Performance thresholds in tests are hard failures, not warnings:
  - PII scrub: < 50 ms for a 10,000-character prompt with 50 PII instances
  - Trace endpoint: p99 < 200 ms under 50 concurrent readers
  - 500-task stress test: < 60 seconds on CI
- Coverage targets: ≥ 90% line coverage on orchestrator; ≥ 95% line and 100%
  branch coverage on guardrails. Coverage regressions block merges.

### Security
- Secrets are never hardcoded. All credentials are sourced from environment
  variables (Phase 1–2) and HashiCorp Vault (Phase 4+).
- JIT tokens are scoped, short-lived, and carry a unique `jti`. Token reuse
  across Temporal retries is a hard test failure.
- OPA is the single source of truth for policy decisions. Hardcoded
  allow/deny logic in application code is not permitted.
- The system must fail closed. If OPA returns a `503`, the request is denied.
  Silent failure-open is never acceptable.

### Observability
- Every orchestrator stage must emit a named OTel span.
  Span names are: `pre-pii-scrub`, `policy-eval`, `jit-token-issue`,
  `llm-invoke`, `post-sanitize`.
- Every stage outcome, error, and lifecycle transition must emit a structured
  audit event validated against `docs/audit-event-schema.json`.
- Prometheus metrics must emit on every task completion **and** every error
  path. Silent metric drops on error are a test failure condition.

### Documentation
- `docs/` is a first-class deliverable, not an afterthought. Documentation
  is peer-reviewed and tested (links, quickstart code blocks, schema
  conformance) as part of each phase gate.
- Runbooks in `docs/runbooks/` must be executable — every shell command is
  extracted and run in CI. A runbook with an untestable command is incomplete.
- The audit event schema (`docs/audit-event-schema.json`) is the open
  standard output. It is versioned, linted, and conformance-tested on every
  commit touching `src/audit_vault/logger.py`.

### Git Hygiene
- `main` must always be green. Never merge a branch that breaks `pytest`,
  `mypy`, or `ruff`.
- `CHANGELOG.md` is updated with every versioned release. Entries describe
  shipped capabilities, not just changed files.
- Commit messages follow the Conventional Commits specification
  (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`).

---

## Development Environment

### Conda Environment: `aegis`

**The `aegis` conda environment is the sole sanctioned Python environment for
this project.** Do not use `venv`, `virtualenv`, `pipenv`, Poetry-managed
venvs, or the system Python interpreter for any development, testing, or
package installation task.

#### Activating the environment

```bash
conda activate aegis
```

Always confirm the environment is active before running any command:

```bash
conda info --envs   # aegis should have an asterisk
python --version    # must be 3.11.x or later
```

#### Installing packages

```bash
# Install the project in editable mode (includes all dev dependencies)
conda activate aegis
pip install -e ".[dev]"

# Adding a new runtime dependency
conda activate aegis
pip install <package>
# Then add it to pyproject.toml [project.dependencies] and commit

# Adding a new dev-only dependency
conda activate aegis
pip install <package>
# Then add it to pyproject.toml [project.optional-dependencies] dev and commit
```

Never `pip install` a package without also recording it in `pyproject.toml`.
Undocumented dependencies break reproducible builds.

#### Running tests

```bash
conda activate aegis
pytest                          # full suite with coverage
pytest tests/test_guardrails.py # single file
pytest -k "pii"                 # filter by name
pytest --cov=src --cov-report=html  # HTML coverage report
```

#### Running linters and type checks

```bash
conda activate aegis
ruff check src/ tests/
mypy src/
```

#### Running the stack locally

```bash
conda activate aegis
docker-compose up -d            # starts OPA, Prometheus, and supporting services
uvicorn src.main:app --reload   # starts the API on http://localhost:8000
```

#### Pre-commit hooks

```bash
conda activate aegis
pre-commit install              # installs hooks into .git/hooks
pre-commit run --all-files      # manual run against all files
```

Pre-commit runs `ruff`, `mypy`, the branding scan, and the audit schema
conformance check on every commit. Hooks must pass before a commit is accepted.

#### Environment reproducibility

If you add or remove dependencies, export the updated environment spec:

```bash
conda activate aegis
pip list --format=freeze > requirements-dev.txt
```

This file is committed alongside `pyproject.toml` changes to allow exact
environment reconstruction on CI and other developer machines.

---

## Key Conventions for Copilot Suggestions

When generating or completing code in this repository:

1. **Activate `aegis` first.** Any shell command suggestion for installing
   packages, running tests, or starting services must use `conda activate aegis`
   — never `python -m venv`, `virtualenv`, or bare `pip install` without the
   environment being active.

2. **No stubs in production paths.** If a feature is not yet implemented,
   raise `NotImplementedError` with a descriptive message. Do not use `pass`
   or `...` silently.

3. **Type-annotate everything.** All function signatures must have complete
   parameter and return type annotations compatible with `mypy --strict`.

4. **Test the behaviour, not the mock.** When writing a test, the assertion
   should verify the contract of the function under test, not the call count
   of an internal implementation detail (unless the call count is itself the
   contract, e.g., "LLM adapter must not be called after budget exhaustion").

5. **Audit events are mandatory.** Any new code path that changes agent state,
   makes a policy decision, or handles an error must emit a corresponding
   `AuditLogger` event. Silently swallowed exceptions are never acceptable.

6. **OTel spans are mandatory.** Any new orchestrator stage or significant
   async operation must open and close a named OTel span. Unclosed spans are
   test failures.

7. **Match the `docs/roadmap.md` item IDs.** When implementing a roadmap
   item (e.g., P1-1, S2-3, W3-2), reference the item ID in the commit
   message (`feat(P2-1): implement AgentTaskWorkflow Temporal activities`).
   This ties implementation commits to gate requirements.

8. **Rego policies are the authority.** Never replicate policy logic in Python.
   If a policy decision is needed, it must go through `OPAClient.evaluate()`.
   The OPA server must fail closed — never assume an unavailable OPA means
   "allow".

9. **Decimal arithmetic for money.** All token cost and budget calculations
   use `decimal.Decimal`, never `float`. Floating-point representation of
   currency is a hard failure condition.

10. **Structured logging only.** Use `structlog` for all log output. Plain
    `print()` statements and unstructured `logging.info()` calls are not
    permitted in production paths.
