"""Completeness checks for Phase 2 deployment guide content."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
GUIDE_PATH = REPO_ROOT / "docs" / "deployment-guide.md"


def test_deployment_guide_contains_temporal_ui_link() -> None:
    content = GUIDE_PATH.read_text(encoding="utf-8")
    assert "http://localhost:18080" in content


def test_deployment_guide_contains_workflow_state_diagram_states() -> None:
    content = GUIDE_PATH.read_text(encoding="utf-8").lower()
    for state in ["running", "pending-approval", "approved", "denied", "completed", "failed"]:
        assert state in content, f"Missing workflow state {state!r} from deployment guide"


def test_deployment_guide_contains_numbered_recovery_procedure() -> None:
    content = GUIDE_PATH.read_text(encoding="utf-8")
    assert "### Recovery procedure" in content
    assert re.search(r"\n1\. ", content), "Expected a numbered recovery procedure"
    for term in ["restart", "Temporal", "task_id"]:
        assert term in content, f"Missing recovery term {term!r} from deployment guide"
