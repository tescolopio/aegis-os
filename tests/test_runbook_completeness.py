"""Completeness checks for Phase 2 HITL runbooks."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
HITL_RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "hitl-stuck-approval.md"
BUDGET_RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "budget-exceeded.md"


def test_hitl_runbook_contains_required_sections() -> None:
    content = HITL_RUNBOOK.read_text(encoding="utf-8")
    for section in ["## Symptoms", "## Diagnosis", "## Escalation", "## Resolution"]:
        assert section in content, f"Missing section {section!r} in HITL runbook"


def test_budget_runbook_contains_phase2_hitl_terms() -> None:
    content = BUDGET_RUNBOOK.read_text(encoding="utf-8")
    for term in ["PendingApproval", "approve", "deny"]:
        assert term in content, f"Missing term {term!r} in budget runbook"
    assert "## HITL Approval Flow" in content


def test_runbooks_do_not_reference_legacy_hitl_endpoints() -> None:
    hitl_content = HITL_RUNBOOK.read_text(encoding="utf-8")
    budget_content = BUDGET_RUNBOOK.read_text(encoding="utf-8")
    legacy_paths = [
        "/api/v1/workflows/{id}/approve",
        "/api/v1/workflows/{id}/deny",
        "/api/v1/approvals",
    ]
    for path in legacy_paths:
        assert path not in hitl_content
        assert path not in budget_content
