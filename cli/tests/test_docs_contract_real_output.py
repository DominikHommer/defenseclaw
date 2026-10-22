# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Pages that quote command output quote what the command prints."""

import io
import os
import re
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from click.testing import CliRunner
from defenseclaw import config, ux
from defenseclaw.commands import cmd_doctor, cmd_guardrail, cmd_setup
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.context import AppContext

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


def _page(rel: str) -> str:
    return (DOCS / rel).read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _text_blocks(text: str) -> list[str]:
    return re.findall(r"```text\n(.*?)```", text, flags=re.S)


@pytest.fixture(autouse=True)
def _unicode_output():
    # The quoted output carries Unicode glyphs; TERM=dumb or another test's
    # console snapshot must not swap them for ASCII.
    with (
        mock.patch.object(ux, "_configured_unicode_output", True),
        mock.patch.dict(os.environ, {"TERM": "xterm-256color"}),
    ):
        yield


# GAP-0567: the Hermes page said doctor reports no failed check, but doctor
# fails the Hermes hooks row while any Hermes host runs and passes once all
# are closed. The page quotes both rows as doctor prints them.
@pytest.mark.parametrize(("running", "tag"), [(True, "[FAIL]"), (False, "[PASS]")])
def test_hermes_page_quotes_the_doctor_row(tmp_path, running, tag):
    hook = tmp_path / ".hermes" / "config.yaml"
    hook.parent.mkdir()
    hook.write_text("hooks:\n  - command: /x/hooks/hermes-hook.sh\n", encoding="utf-8")
    cfg = mock.MagicMock()
    cfg.data_dir = str(tmp_path)
    r = _DoctorResult()
    out = io.StringIO()
    with (
        mock.patch.object(cmd_doctor, "_hook_health_paths_from_lock", return_value=[str(hook)]),
        mock.patch.object(cmd_doctor, "_hermes_host_running", return_value=running),
        mock.patch.object(cmd_doctor, "_json_mode", False),
        mock.patch.object(cmd_doctor.ux, "_color_enabled", return_value=False),
        cmd_doctor._doctor_label_suffix("[hermes]"),
        redirect_stdout(out),
    ):
        cmd_doctor._check_hook_health(cfg, "hermes", r)
    row = r.checks[-1]
    assert row["status"] == ("fail" if running else "pass")
    page = _flat(_page("connectors/hermes.mdx"))
    detail = _flat(row["detail"].replace(str(hook), "~/.hermes/config.yaml"))
    assert detail in page, detail
    if running:
        line = out.getvalue().splitlines()[0].strip().replace(str(hook), "~/.hermes/config.yaml")
        assert line.startswith(f"{tag} Hermes hooks [hermes]"), line
        assert line + "\n" in _text_blocks(_page("connectors/hermes.mdx")), line
    assert "reports no failed check" not in page
    # Setup prints a restart hint, not a pending_reload state, and doctor
    # has no such row. Only the gateway's state file holds pending_reload.
    hint = f"! ({cmd_setup._pending_reload_hint('hermes')})"
    reference = _flat(_page("reference/connectors/hermes.mdx"))
    assert hint in page and hint in reference
    assert "pending_reload" not in page
    assert re.findall(r"`[^`]*pending_reload[^`]*`", reference) == ['`"status": "pending_reload"`'], reference


def _fail_mode_view(tmp_path, body: str) -> str:
    (tmp_path / "config.yaml").write_text(body, encoding="utf-8")
    app = AppContext()
    app.cfg = config.load(data_dir=tmp_path)
    gc = app.cfg.guardrail

    def installed(_cfg, name, **_kw):
        mode = gc.effective_hook_fail_mode(name)
        return SimpleNamespace(runtime=mode, desired=mode, effective=mode, drift=(), note="")

    with mock.patch.object(cmd_guardrail, "resolve_connector_fail_mode", side_effect=installed):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
    assert result.exit_code == 0, result.output
    return result.output


_ROSTER = (
    "config_version: 9\n"
    "guardrail:\n"
    "  enabled: true\n"
    "  connector: claudecode\n"
    "  hook_fail_mode: {global_mode}\n"
    "  connectors:\n"
    "    claudecode: {claude}\n"
    "    codex: {codex}\n"
)


# GAP-0576: the example mixed the closed footer into an open global value.
# Each quoted block is the command's real output for its configuration.
def test_fail_mode_page_quotes_the_real_output(tmp_path):
    blocks = _text_blocks(_page("reference/configuration/fail-modes.mdx"))
    open_view = _fail_mode_view(
        tmp_path, _ROSTER.format(global_mode="open", claude="{}", codex="{hook_fail_mode: closed}")
    )
    assert open_view.strip("\n") + "\n" in blocks, open_view
    closed_view = _fail_mode_view(
        tmp_path, _ROSTER.format(global_mode="closed", claude="{hook_fail_mode: open}", codex="{}")
    )
    footer = closed_view[closed_view.index("  Invalid,"):].strip("\n") + "\n"
    assert footer in blocks, closed_view
