"""Static checks for the Docker Compose Temporal worker service."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"


def test_docker_compose_defines_aegis_worker_service() -> None:
    content = COMPOSE_PATH.read_text(encoding="utf-8")
    assert "aegis-worker:" in content
    assert 'python", "-m", "src.control_plane.worker"' in content
    assert "AEGIS_TEMPORAL_TASK_QUEUE=aegis-agent-tasks" in content
