"""AI Runtime enforcing-host stat reflects each host's latest reported state."""

from __future__ import annotations

import json
from pathlib import Path


DASHBOARD = (
    Path(__file__).resolve().parents[2]
    / "bundles/local_observability_stack/grafana/dashboards/defenseclaw-ai-runtime.json"
)


def test_enforcing_hosts_uses_latest_plane_health_per_host() -> None:
    board = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    by_title = {panel.get("title"): panel for panel in board["panels"]}
    stat = by_title["Hosts with enforcing controls"]
    assert stat["type"] == "stat"
    assert len(stat["targets"]) == 1
    expr = stat["targets"][0]["expr"]

    assert expr.startswith("count((") and expr.endswith(") > 0) or vector(0)")
    assert expr.count('event_name="ai.runtime.plane_health"') == 2
    assert expr.count('body_defenseclaw_ai_runtime_plane="c"') == 2
    assert "unwrap body_defenseclaw_ai_runtime_kernel_users_enforced" in expr
    assert "last_over_time(" in expr and "[10m]" in expr
    assert " and on (host_name, " in expr
    assert "topk by (host_name) (1, " in expr
    assert "{{ __timestamp__ | unixEpoch }}" in expr and "unwrap ts" in expr
    assert 'host_name=~"$host"' in expr
    assert "$user" not in expr
    assert "count_over_time" not in expr and "ai.runtime.kernel_policy" not in expr
    assert "latest" in stat["description"].lower() and "10 minutes" in stat["description"]

    user = next(v for v in board["templating"]["list"] if v["name"] == "user")
    assert "Hosts with enforcing controls" in user["description"]

    policy = by_title["DefenseClaw kernel policies"]
    description = policy["description"]
    assert "counts" in description.lower() and "change events" in description.lower()
    assert "Hosts with enforcing controls" in description
    assert "Kernel controls per host" in description
