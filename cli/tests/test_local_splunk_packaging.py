# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A fresh wheel owns the complete native Local Splunk runtime."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "bundles" / "splunk_local_bridge"


@pytest.mark.skipif(os.name == "nt", reason="POSIX bind-mount permissions")
def test_app_packages_are_container_readable_under_private_umask(tmp_path: Path, monkeypatch) -> None:
    from defenseclaw.observability.local_splunk import NativeLocalSplunkController, package_splunk_app
    from defenseclaw.observability.local_stack import LocalStackError

    stack = tmp_path / "stack"
    shutil.copytree(BUNDLE, stack)
    archive = stack / "splunk" / "build" / "defenseclaw_local_mode.tgz"
    # Both the Unix bridge and the native controller rebuild this mounted
    # public asset. Neither may inherit the operator's private file modes.
    for packager in ("shell", "native"):
        if archive.parent.exists():
            shutil.rmtree(archive.parent)
        if packager == "shell":
            completed = subprocess.run(
                ["bash", str(stack / "splunk" / "package_local_mode_app.sh")],
                capture_output=True, text=True, umask=0o077, timeout=30, check=False,
            )
            assert completed.returncode == 0, completed.stderr
        else:
            previous = os.umask(0o077)
            try:
                package_splunk_app(stack)
            finally:
                os.umask(previous)
        assert stat.S_IMODE(archive.parent.stat().st_mode) == 0o755
        assert stat.S_IMODE(archive.stat().st_mode) == 0o644

    # Healthy listeners alone cannot prove that Splunk installed the app.
    bridge = (BUNDLE / "bin" / "splunk-claw-bridge").read_text(encoding="utf-8")
    readiness = bridge[bridge.index("wait_for_hec_ready() {"):bridge.index("\nprint_up_text() {")]
    probe = tmp_path / "readiness.sh"
    probe.write_text(
        'set -euo pipefail\nDEFENSECLAW_HEC_TOKEN="fixture credential"\n'
        'DEFENSECLAW_HEC_URL="https://127.0.0.1:8088/services/collector/event"\n'
        'SERVICE_NAME=splunk\ncurl() { printf 200; }\n'
        'run_compose() { [[ "$APP_READY" == true ]]; }\n'
        'service_restart_count() { echo 2; }\ncompose_project_name() { echo fixture; }\n'
        'fail() { printf "%s\\n" "$1" >&2; exit 1; }\n'
        + readiness + '\nwait_for_hec_ready\n', encoding="utf-8",
    )
    for ready in (False, True):
        result = subprocess.run(
            ["bash", str(probe)], env={**os.environ, "APP_READY": str(ready).lower()},
            capture_output=True, text=True, timeout=10, check=False,
        )
        assert (result.returncode == 0) is ready, result.stdout + result.stderr

    controller = NativeLocalSplunkController(stack, docker_path="docker")
    monkeypatch.setattr(controller, "_web_ready", lambda _timeout: True)
    monkeypatch.setattr(controller, "_hec_ready", lambda _timeout: True)
    compose = Mock(return_value=SimpleNamespace(returncode=1))
    monkeypatch.setattr(controller, "_run_compose", compose)
    with pytest.raises(LocalStackError, match="readiness timeout"):
        controller.wait_for_readiness(1)
    compose.return_value.returncode = 0
    controller.wait_for_readiness(1)
    assert "test" in compose.call_args.args


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required to build wheels")
def test_wheel_resolves_complete_splunk_bundle_outside_checkout(
    tmp_path: Path,
) -> None:
    output = tmp_path / "wheel"
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [shutil.which("uv"), "build", "--wheel", "--out-dir", str(output)],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=240,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]
    wheel = next(output.glob("defenseclaw-*.whl"))
    expected_assets = {
        path.relative_to(BUNDLE).as_posix()
        for path in BUNDLE.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
    prefix = "defenseclaw/_data/splunk_local_bridge/"
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        packaged_assets = {name.removeprefix(prefix) for name in names if name.startswith(prefix)}
        assert expected_assets <= packaged_assets
        for relative_path in expected_assets:
            assert archive.read(prefix + relative_path) == (BUNDLE / Path(relative_path)).read_bytes(), (
                f"packaged Local Splunk asset drifted: {relative_path}"
            )
        assert "defenseclaw/observability/local_splunk.py" in names
        archive.extractall(tmp_path / "site")

    probe = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import pathlib,sys;sys.path.insert(0,sys.argv[1]);"
                "from defenseclaw.paths import bundled_splunk_bridge_dir;"
                "from defenseclaw.observability.local_splunk import validate_bundle_assets;"
                "p=validate_bundle_assets(bundled_splunk_bridge_dir());"
                "assert (p/'compose'/'docker-compose.local.yml').is_file();"
                "assert (p/'splunk'/'apps'/'defenseclaw_local_mode'/'lookups'/'dcso_risk_state_labels.csv').is_file();"
                "assert (p/'splunk'/'apps'/'defenseclaw_local_mode'/'lookups'/'dcso_severity_labels.csv').is_file();"
                "assert sys.argv[2] not in str(p);print(p)"
            ),
            str(tmp_path / "site"),
            str(REPO_ROOT),
        ],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    assert "_data" in probe.stdout
