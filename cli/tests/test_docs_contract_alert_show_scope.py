# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""`defenseclaw alerts --show N` numbers the list it is run with. A docs page
that lists alerts and then shows one by number must give --show the same
--connector as the list, and N must fall within both --limit windows, or N
picks a row of another list
(GAP-0611 on ask-before-risky-calls.mdx, the same defect on
write-a-custom-rule.mdx). Every such pair is checked and run."""

from __future__ import annotations

import json
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

DOCS = Path(__file__).resolve().parents[2] / "docs-site/content/docs"


def _alerts_args(line: str) -> list[str] | None:
    line = line.strip().removeprefix("$ ")
    if not line.startswith("defenseclaw alerts"):
        return None
    args = shlex.split(line, comments=True)[2:]
    # `alerts acknowledge` / `alerts dismiss` neither list nor show.
    return None if args[:1] and not args[0].startswith("-") else args


def _pairs() -> list[tuple[str, list[str] | None, list[str]]]:
    """(page § section, latest list command before it in the section, --show command)."""
    pairs = []
    for page in sorted(DOCS.rglob("*.md*")):
        for n, section in enumerate(page.read_text(encoding="utf-8").split("\n## ")):
            title = section.splitlines()[0] if n else "intro"
            listed = None
            for block in re.findall(r"```(?:bash|sh|shell)\n(.*?)```", section, re.S):
                for line in block.splitlines():
                    args = _alerts_args(line)
                    if args is None:
                        continue
                    if "--show" in args:
                        pairs.append((f"{page.relative_to(DOCS)} § {title}", listed, args))
                    else:
                        listed = args
    return pairs


PAIRS = _pairs()


def _option(args: list[str], *names: str, default: str | None = None) -> str | None:
    for i, a in enumerate(args):
        for name in names:
            if a == name and i + 1 < len(args):
                return args[i + 1]
            if a.startswith(name + "="):
                return a.split("=", 1)[1]
    return default


def _limit(args: list[str]) -> int:
    return int(_option(args, "--limit", "-n", default="25"))


def test_pages_show_alerts_by_number():
    assert any(listed for _, listed, _ in PAIRS), PAIRS


@pytest.mark.parametrize("where,listed,show", PAIRS, ids=[p[0] for p in PAIRS])
def test_show_uses_the_scope_of_the_list_before_it(where, listed, show):
    if listed is None:
        # Nothing listed in this section: --show N numbers the unfiltered list.
        assert _option(show, "--connector") is None, (where, show)
        return
    assert _option(show, "--connector") == _option(listed, "--connector"), (where, listed, show)
    assert int(_option(show, "--show")) <= min(_limit(listed), _limit(show)), (where, listed, show)


@pytest.fixture
def app():
    app, tmp_dir, db_path = make_app_context()
    yield app
    cleanup_app(app, db_path, tmp_dir)


def _alert(app, connector: str, at: datetime) -> None:
    app.store.log_event(
        Event(
            action="scan-finding",
            target="",
            severity="HIGH",
            connector=connector,
            details="finding.observed",
            timestamp=at,
            structured={
                "defenseclaw.finding.rule_id": "ORG-TEST",
                "defenseclaw.finding.title": "test finding",
                "defenseclaw.scan.scanner": "hook-rules",
            },
        )
    )


@pytest.mark.parametrize("where,listed,show", [p for p in PAIRS if p[1]], ids=[p[0] for p in PAIRS if p[1]])
def test_show_prints_the_row_the_list_numbered(app, where, listed, show):
    # The reader's own test alerts, then newer alerts from another connector
    # and from the gateway (no connector) that move the global numbering.
    connector = _option(listed, "--connector") or "claudecode"
    at = datetime.now(timezone.utc) - timedelta(minutes=10)
    for i in range(int(_option(show, "--show"))):
        _alert(app, connector, at + timedelta(seconds=i))
    for i, other in enumerate(("codex", "")):
        _alert(app, other, at + timedelta(minutes=1, seconds=i))

    runner = CliRunner()
    result = runner.invoke(alerts, [*listed, "--json"], obj=app, catch_exceptions=False)
    assert result.exit_code == 0, (where, result.output)
    rows = json.loads(result.output)
    number = int(_option(show, "--show"))
    shown = runner.invoke(alerts, show, obj=app, catch_exceptions=False)
    assert shown.exit_code == 0, (where, show, shown.output)
    ids = re.findall(r"ID:\s+(\S+)", shown.output)
    assert ids == [rows[number - 1]["id"]], (where, listed, show, shown.output)
