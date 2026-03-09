"""Smoke checks for the PendingApproval demo verification script."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "verify_pending_approval_demo.py"


def test_pending_approval_demo_script_help() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )

    assert result.returncode == 0
    assert "Verify the live PendingApproval demo flow" in result.stdout
    assert "--action" in result.stdout
    assert "--api-base-url" in result.stdout
