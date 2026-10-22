# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0611: the "Check it worked" commands of ask-before-risky-calls.mdx run
against the audit rows the page's steps leave (deny once, approve once, then
Claude Code's reply that quotes the URL) and print what the page shows."""

from __future__ import annotations

import os
import re
import shlex
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.models import Event

from tests.helpers import cleanup_app, make_app_context

PAGE = Path(__file__).resolve().parents[2] / "docs-site/content/docs/how-to/guardrail/ask-before-risky-calls.mdx"
RULE = {
    "defenseclaw.finding.rule_id": "C2-WEBHOOK-SITE",
    "defenseclaw.finding.title": "webhook.site (known exfil)",
    "defenseclaw.scan.scanner": "hook-rules",
}


def _section() -> str:
    text = PAGE.read_text(encoding="utf-8")
    return text.split("## Check it worked", 1)[1].split("\n## ", 1)[0]


def _commands() -> list[list[str]]:
    blocks = re.findall(r"```bash\n(.*?)```", _section(), re.S)
    commands = [shlex.split(line) for block in blocks for line in block.splitlines() if line.strip()]
    assert commands and all(c[:2] == ["defenseclaw", "alerts"] for c in commands), commands
    return [c[2:] for c in commands]


@pytest.fixture
def app():
    app, tmp_dir, db_path = make_app_context()
    columns = {row[1] for row in app.store.db.execute("PRAGMA table_info(audit_events)")}
    if "request_id" not in columns:
        app.store.db.execute("ALTER TABLE audit_events ADD COLUMN request_id TEXT")
    saved_columns = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = "240"
    yield app
    cleanup_app(app, db_path, tmp_dir)
    if saved_columns is None:
        os.environ.pop("COLUMNS", None)
    else:
        os.environ["COLUMNS"] = saved_columns


def _hook_finding(app, request_id: str, hook_event: str, action: str, at: datetime) -> None:
    """The connector-hook row and the hook-rule finding the gateway writes for one hook call."""
    hook = Event(
        action="connector-hook",
        target=hook_event,
        severity="INFO",
        connector="claudecode",
        details=f"connector=claudecode action={action} severity=HIGH",
        timestamp=at,
    )
    finding = Event(
        action="scan-finding",
        target="",
        severity="HIGH",
        connector="claudecode",
        details="finding.observed",
        timestamp=at,
        structured={**RULE, "defenseclaw.finding.target_ref": f"claudecode:{hook_event}"},
    )
    app.store.log_event(hook)
    app.store.log_event(finding)
    app.store.db.execute("UPDATE audit_events SET request_id=? WHERE id IN (?, ?)", (request_id, hook.id, finding.id))
    app.store.db.commit()


def _field_run(app) -> None:
    start = datetime.now(timezone.utc) - timedelta(minutes=5)
    _hook_finding(app, "req-deny", "PreToolUse", "confirm", start)
    _hook_finding(app, "req-approve", "PreToolUse", "confirm", start + timedelta(seconds=48))
    # The reply after the approved run quotes the URL (T6Z2-11).
    _hook_finding(app, "req-reply", "MessageDisplay", "alert", start + timedelta(seconds=69))


def _expected_lines() -> list[str]:
    blocks = re.findall(r"```text\n(.*?)```", _section(), re.S)
    assert len(blocks) == 1, blocks
    return [line.rstrip() for line in blocks[0].splitlines() if line.strip() and line.strip() != "…"]


def _same_line(page: str, shown: str) -> bool:
    # The ID and the timestamp differ per run.
    label = page.split(":", 1)[0].strip()
    if label in {"ID", "Timestamp"}:
        return shown.split(":", 1)[0].strip() == label
    return " ".join(page.split()) == " ".join(shown.split())


def test_check_it_worked_shows_the_confirm_alert(app):
    _field_run(app)
    runner = CliRunner()
    outputs = []
    for args in _commands():
        result = runner.invoke(alerts, args, obj=app, catch_exceptions=False)
        assert result.exit_code == 0, (args, result.output)
        outputs.append((args, result.output))

    show_args, shown = next((a, o) for a, o in outputs if "--show" in a)
    lines = shown.splitlines()
    at = 0
    for expected in _expected_lines():
        while at < len(lines) and not _same_line(expected, lines[at]):
            at += 1
        assert at < len(lines), (show_args, expected, shown)
        at += 1

    listed = [o for a, o in outputs if "--show" not in a]
    assert listed, "the page lists the alerts before it picks one"
    targets = re.findall(r"claudecode:(PreToolUse|MessageDisplay)\s*[|│]\s*decision=(\w+)", listed[0])
    assert targets == [("MessageDisplay", "alert"), ("PreToolUse", "confirm"), ("PreToolUse", "confirm")], listed[0]
    newest_confirm = 1 + targets.index(("PreToolUse", "confirm"))
    assert show_args[show_args.index("--show") + 1] == str(newest_confirm)


def test_check_it_worked_names_the_later_reply_alert():
    text = " ".join(_section().split())
    assert "a newer `claudecode:MessageDisplay` row with `decision=alert`" in text
    assert "`claudecode:PreToolUse` row with `decision=confirm`" in text
