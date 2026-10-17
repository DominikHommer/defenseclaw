"""The shipped runtime charts count findings rather than repeated activity rows."""

from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]


def test_grafana_no_hook_and_would_block_count_distinct_findings() -> None:
    dashboard = json.loads(
        (ROOT / "bundles/local_observability_stack/grafana/dashboards/defenseclaw-ai-runtime.json")
        .read_text(encoding="utf-8")
    )
    panels = {panel["title"]: panel for panel in dashboard["panels"]}
    no_hook = panels["Agent activity with no hook decision"]
    control = panels["Would-block in monitor mode, by control"]
    for panel in (no_hook, control):
        target = panel["targets"][0]
        expression = target["expr"]
        assert "body_defenseclaw_ai_runtime_finding_id" in expression
        assert "sum by (host_name, body_defenseclaw_ai_runtime_finding_id" in expression
        assert "[$__range]" in expression
        assert target["instant"] is True
    assert no_hook["type"] == "stat"
    assert control["type"] == "bargauge"


def test_splunk_timecharts_keep_first_sighting_bucket() -> None:
    view = ET.parse(
        ROOT
        / "bundles/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/default/data/ui/views/ai_runtime_planes.xml"
    )
    panels = {panel.findtext("title"): panel for panel in view.iter("panel")}
    for title, distinct_fields in (
        ("Host-plane tactics by kill-chain stage", "host runtime_finding_id runtime_tactic"),
        ("Would-block by control (monitor mode)", "host runtime_finding_id runtime_kernel_control"),
    ):
        query = panels[title].findtext("chart/search/query")
        assert query is not None
        assert query.index("sort 0 + _time") < query.index(f"dedup {distinct_fields}")
        assert query.index(f"dedup {distinct_fields}") < query.index("timechart span=10m")
