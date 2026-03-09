"""Cross-reference checks between HITL runbooks and the API reference."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
API_REFERENCE = REPO_ROOT / "docs" / "api-reference.md"
RUNBOOKS = [
    REPO_ROOT / "docs" / "runbooks" / "hitl-stuck-approval.md",
    REPO_ROOT / "docs" / "runbooks" / "budget-exceeded.md",
]

_ENDPOINT_RE = re.compile(r"/api/v1/[A-Za-z0-9_{}\-/]+")


def _normalize_task_endpoint(path: str) -> str:
    """Normalize shell-expanded task paths to the documented template form."""
    return (
        path.replace("${TASK_ID}", "{task_id}")
        .replace("$TASK_ID", "{task_id}")
        .replace("//", "/")
    )


def test_runbook_endpoint_paths_are_documented_in_api_reference() -> None:
    api_endpoints = {
        _normalize_task_endpoint(path)
        for path in _ENDPOINT_RE.findall(API_REFERENCE.read_text(encoding="utf-8"))
        if path.startswith("/api/v1/tasks/")
    }
    runbook_endpoints: set[str] = set()
    for runbook in RUNBOOKS:
        runbook_endpoints.update(
            _normalize_task_endpoint(path)
            for path in _ENDPOINT_RE.findall(runbook.read_text(encoding="utf-8"))
            if "/tasks/" in path and ("approve" in path or "deny" in path)
        )

    undocumented = sorted(runbook_endpoints - api_endpoints)
    assert undocumented == [], (
        "Runbooks reference endpoints missing from docs/api-reference.md:\n"
        + "\n".join(f"  - {path}" for path in undocumented)
    )
