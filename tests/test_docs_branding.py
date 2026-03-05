"""Tests for F1-2: Aegis Governance Loop branding consistency.

Test coverage:
  1. Negative scan — zero occurrences of "Governance Sandwich" in all
     user-facing .md files under docs/ and in README.md.
  2. Positive presence — at least one occurrence of "Aegis Governance Loop"
     in README.md and in docs/roadmap.md.

docs/roadmap.md is intentionally excluded from the negative scan because it is
a living planning document that necessarily references the old term in the
descriptions of F1-2 task steps and historical checklist items.  All other .md
files under docs/ must be free of the deprecated term.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
DOCS_DIR = REPO_ROOT / "docs"
README = REPO_ROOT / "README.md"

# The roadmap describes the task itself so it references the old term as
# meta-text.  Exclude it from the negative branding scan.
_EXCLUDED_FROM_NEGATIVE_SCAN = {DOCS_DIR / "roadmap.md"}

DEPRECATED_TERM = "governance sandwich"
CANONICAL_TERM = "Aegis Governance Loop"


def _md_files_to_scan() -> list[Path]:
    """All .md files under docs/ (except excluded) plus README.md."""
    docs_files = [
        p for p in DOCS_DIR.rglob("*.md") if p not in _EXCLUDED_FROM_NEGATIVE_SCAN
    ]
    return docs_files + [README]


# ---------------------------------------------------------------------------
# 1 – Negative scan: zero occurrences of deprecated term
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("md_path", _md_files_to_scan(), ids=lambda p: p.name)
def test_no_governance_sandwich_in_file(md_path: Path) -> None:
    """The deprecated term 'Governance Sandwich' must not appear in this file."""
    content = md_path.read_text(encoding="utf-8")
    occurrences = content.lower().count(DEPRECATED_TERM.lower())
    assert occurrences == 0, (
        f"Found {occurrences} occurrence(s) of '{DEPRECATED_TERM}' in "
        f"{md_path.relative_to(REPO_ROOT)!s}. "
        f"Replace all with '{CANONICAL_TERM}'."
    )


def test_no_governance_sandwich_across_all_docs() -> None:
    """Bulk assertion: every scanned file must be free of the deprecated term."""
    violations: list[str] = []
    for md_path in _md_files_to_scan():
        content = md_path.read_text(encoding="utf-8")
        count = content.lower().count(DEPRECATED_TERM.lower())
        if count > 0:
            violations.append(f"{md_path.relative_to(REPO_ROOT)}: {count} occurrence(s)")
    assert violations == [], (
        "Deprecated branding found in the following files:\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


# ---------------------------------------------------------------------------
# 2 – Positive presence: canonical term must appear in key docs
# ---------------------------------------------------------------------------


def test_canonical_term_in_readme() -> None:
    """README.md must contain at least one occurrence of 'Aegis Governance Loop'."""
    content = README.read_text(encoding="utf-8")
    assert CANONICAL_TERM in content, (
        f"'{CANONICAL_TERM}' not found in README.md — "
        "the canonical branding may have been accidentally removed."
    )


def test_canonical_term_in_roadmap() -> None:
    """docs/roadmap.md must contain at least one occurrence of 'Aegis Governance Loop'."""
    roadmap = DOCS_DIR / "roadmap.md"
    content = roadmap.read_text(encoding="utf-8")
    assert CANONICAL_TERM in content, (
        f"'{CANONICAL_TERM}' not found in docs/roadmap.md — "
        "the canonical branding may have been accidentally removed."
    )


def test_canonical_term_in_agent_sdk_guide() -> None:
    """docs/agent-sdk-guide.md must contain at least one occurrence of 'Aegis Governance Loop'."""
    guide = DOCS_DIR / "agent-sdk-guide.md"
    content = guide.read_text(encoding="utf-8")
    assert CANONICAL_TERM in content, (
        f"'{CANONICAL_TERM}' not found in docs/agent-sdk-guide.md — "
        "the guide must reference the open standard by its canonical name."
    )
