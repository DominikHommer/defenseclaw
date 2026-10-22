# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The install page shows what doctor prints right after a plain install."""

import os
import re
import subprocess
import sys
from pathlib import Path, PureWindowsPath

import pytest
from click.testing import CliRunner
from defenseclaw.main import cli

PAGE = Path(__file__).resolve().parents[2] / "docs-site/content/docs/get-started/install.mdx"


@pytest.mark.parametrize("flavor", ["native", "windows"])
def test_install_page_shows_doctor_before_init(tmp_path, monkeypatch: pytest.MonkeyPatch, flavor: str) -> None:
    """GAP-0562: before init, doctor prints only the Config file row; the page must say so.

    The page is for every OS, so the row must match with Windows paths too.
    """
    home = tmp_path / "home"
    data_dir = home / ".defenseclaw"
    data_dir.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(data_dir))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    shown_home = str(home)
    if flavor == "windows":
        shown_home = r"C:\Users\dev\home"
        monkeypatch.setattr(
            "defenseclaw.config.config_path_for_data_dir",
            lambda _data_dir=None: PureWindowsPath(shown_home, ".defenseclaw", "config.yaml"),
        )

    result = CliRunner().invoke(cli, ["doctor"])
    rows = [
        line.replace(shown_home, "~").replace("\\", "/")
        for line in result.output.splitlines()
        if re.match(r"\s*\[[A-Z]+\]", line)
    ]
    assert len(rows) == 1 and "[FAIL] Config file" in rows[0], result.output

    text = PAGE.read_text(encoding="utf-8")
    section = text.split("## Check it worked", 1)[1].split("\n## ", 1)[0]
    assert "After init" in section, "the page must say what doctor shows before and after init"
    before, after = section.split("After init", 1)
    assert "defenseclaw init --connector <agent>` before `defenseclaw doctor`" in before
    assert f"exits {result.exit_code}" in before
    shown = re.findall(r"```text\n(.*?)```", before.split("defenseclaw doctor", 1)[1], re.S)
    assert [line for line in shown[0].splitlines() if line.strip()] == rows
    assert "`defenseclaw doctor`" in after


@pytest.mark.skipif(sys.platform == "win32", reason="forces a non-UTF-8 POSIX locale")
def test_install_page_check_passes_without_utf8_locale() -> None:
    """Windows CI runs without PYTHONUTF8, so the page must not be read with the locale codec."""
    env = {**os.environ, "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0", "LC_ALL": "C", "LANG": "C"}
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"{__file__}::test_install_page_shows_doctor_before_init",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
