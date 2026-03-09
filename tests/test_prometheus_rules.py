"""Validation checks for the W2-3 Prometheus HITL alert rule."""

from __future__ import annotations

import contextlib
import http.server
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

import httpx
import pytest

REPO_ROOT = Path(__file__).parent.parent
PROMETHEUS_CONFIG_PATH = REPO_ROOT / "docs" / "prometheus.yml"
ALERTS_PATH = REPO_ROOT / "docs" / "alerts.yml"
RUNBOOK_PATH = "docs/runbooks/hitl-stuck-approval.md"
PROMETHEUS_IMAGE = "prom/prometheus:v2.53.1"


class _MetricsHandler(http.server.BaseHTTPRequestHandler):
    """Serve a single synthetic Prometheus metric payload."""

    metric_text = ""

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/metrics":
            self.send_error(404)
            return

        payload = self.metric_text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


@contextlib.contextmanager
def _serve_metric(metric_value: int) -> Iterator[str]:
    metric_text = (
        "# TYPE aegis_workflow_pending_approval_seconds gauge\n"
        f'aegis_workflow_pending_approval_seconds{{workflow_id="wf-123"}} {metric_value}\n'
    )
    handler = type("MetricsHandler", (_MetricsHandler,), {"metric_text": metric_text})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"host.docker.internal:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@contextlib.contextmanager
def _run_prometheus(*, scrape_target: str | None, shorten_for_clause: bool) -> Iterator[str]:
    try:
        from testcontainers.core.container import DockerContainer
    except ImportError:
        pytest.skip("testcontainers not installed; skipping Prometheus container tests")

    prometheus_config = PROMETHEUS_CONFIG_PATH.read_text(encoding="utf-8")
    alerts_config = ALERTS_PATH.read_text(encoding="utf-8")

    if scrape_target is not None:
        prometheus_config = "\n".join(
            [
                "global:",
                "  scrape_interval: 1s",
                "  evaluation_interval: 1s",
                "",
                "rule_files:",
                '  - "/etc/prometheus/alerts.yml"',
                "",
                "scrape_configs:",
                '  - job_name: "synthetic-hitl"',
                "    static_configs:",
                f'      - targets: ["{scrape_target}"]',
                '    metrics_path: "/metrics"',
            ]
        )
    if shorten_for_clause:
        alerts_config = alerts_config.replace("for: 1m", "for: 0s")

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "prometheus.yml").write_text(prometheus_config, encoding="utf-8")
        (tmp_path / "alerts.yml").write_text(alerts_config, encoding="utf-8")
        os.chmod(tmp_path, 0o755)
        os.chmod(tmp_path / "prometheus.yml", 0o644)
        os.chmod(tmp_path / "alerts.yml", 0o644)

        container = DockerContainer(PROMETHEUS_IMAGE)
        container.with_volume_mapping(str(tmp_path), "/etc/prometheus", mode="ro")
        container.with_exposed_ports(9090)
        container.with_kwargs(extra_hosts={"host.docker.internal": "host-gateway"})

        try:
            container.start()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"Docker unavailable - skipping Prometheus container tests: {exc}")

        try:
            port = _wait_for_exposed_port(container, 9090)
            base_url = f"http://localhost:{port}"
            _wait_for_prometheus(base_url)
            yield base_url
        finally:
            container.stop()


def _wait_for_exposed_port(container: Any, port: int) -> str:
    """Return the mapped host port once Docker publishes it."""
    deadline = time.monotonic() + 10.0
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return str(container.get_exposed_port(port))
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(0.25)
    if last_error is not None:
        raise last_error
    raise RuntimeError(f"Port mapping for {port} was not published")


def _wait_for_prometheus(base_url: str) -> None:
    deadline = time.monotonic() + 30.0
    with httpx.Client(timeout=2.0) as client:
        while time.monotonic() < deadline:
            try:
                ready = client.get(f"{base_url}/-/ready")
                if ready.status_code == 200:
                    rules = client.get(f"{base_url}/api/v1/rules")
                    if rules.status_code == 200:
                        return
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
    pytest.fail("Prometheus container did not become ready in time")


def _get_hitl_rule(base_url: str) -> dict[str, Any]:
    with httpx.Client(timeout=5.0) as client:
        response = client.get(f"{base_url}/api/v1/rules")
        response.raise_for_status()
    payload = response.json()
    groups = payload["data"]["groups"]
    for group in groups:
        for rule in group["rules"]:
            if rule.get("name") == "aegis_hitl_stuck":
                return cast(dict[str, Any], rule)
    pytest.fail("aegis_hitl_stuck alert rule not found in Prometheus API")


def _wait_for_rule_state(base_url: str, expected_state: str) -> dict[str, Any]:
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        rule = _get_hitl_rule(base_url)
        if rule.get("state") == expected_state:
            return rule
        time.sleep(0.5)
    pytest.fail(f"aegis_hitl_stuck did not reach state {expected_state!r} in time")



def test_prometheus_hitl_stuck_syntax() -> None:
    with _run_prometheus(scrape_target=None, shorten_for_clause=False) as base_url:
        rule = _wait_for_rule_state(base_url, "inactive")
    assert rule["health"] in {"ok", "unknown"}
    assert rule.get("lastError", "") == ""


def test_prometheus_hitl_stuck_fires() -> None:
    with _serve_metric(86401) as scrape_target:
        with _run_prometheus(scrape_target=scrape_target, shorten_for_clause=True) as base_url:
            rule = _wait_for_rule_state(base_url, "firing")
    labels = rule["labels"]
    assert labels["severity"] == "critical"


def test_prometheus_hitl_stuck_silent() -> None:
    with _serve_metric(86399) as scrape_target:
        with _run_prometheus(scrape_target=scrape_target, shorten_for_clause=True) as base_url:
            rule = _wait_for_rule_state(base_url, "inactive")
    assert rule["name"] == "aegis_hitl_stuck"


def test_prometheus_runbook_link() -> None:
    content = ALERTS_PATH.read_text(encoding="utf-8")
    assert "alert: aegis_hitl_stuck" in content
    assert "aegis_workflow_pending_approval_seconds" in content
    assert RUNBOOK_PATH in content
    assert 'runbook_url: "docs/runbooks/hitl-stuck-approval.md"' in content
