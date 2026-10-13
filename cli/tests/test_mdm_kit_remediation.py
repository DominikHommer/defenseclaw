import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "packaging/mdm/intune/windows"


@pytest.fixture
def pwsh() -> str:
    executable = os.environ.get("DEFENSECLAW_TEST_PWSH") or shutil.which("pwsh") or shutil.which("pwsh.exe")
    if not executable:
        pytest.skip("PowerShell is unavailable")
    return executable


def _run_script(pwsh: str, tmp_path: Path, script: str, document: dict, exit_code: int = 0) -> str:
    document_path = tmp_path / "lifecycle.json"
    document_path.write_text(json.dumps(document), encoding="utf-8")
    script_path = tmp_path / "harness.ps1"
    script_path.write_text(script, encoding="utf-8")
    env = os.environ.copy()
    env["DC_TEST_DOCUMENT"] = str(document_path)
    env["DC_TEST_EXIT_CODE"] = str(exit_code)
    result = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(script_path)], env=env, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"ok": True, "noop": True, "errors": []}, "0|no repair needed after verify"),
        ({"ok": True, "noop": True, "errors": [], "warnings": [
            {"code": "telemetry_unreachable", "message": "otel down"},
        ]}, "0|no repair needed after verify"),
        ({"ok": True, "noop": False, "errors": [], "changes": ["started guardian"]},
         "0|repaired (drift): started guardian"),
        ({"ok": True, "noop": False, "errors": [], "warnings": [
            {"code": "telemetry_unreachable", "message": "otel down"},
        ], "changes": ["started guardian", "restored config"]},
         "0|repaired (drift): started guardian, restored config"),
        ({"ok": True, "noop": False, "errors": [], "warnings": [
            {"code": "scanner_runtime_unavailable", "message": "runtime missing"},
        ]}, "1603|not repaired (scanner_runtime_unavailable): runtime missing"),
        ({"ok": True, "noop": False, "errors": [], "warnings": [
            {"code": "recovered_pending_transaction", "message": "rolled back"},
        ]}, "0|repaired (recovered_pending_transaction): rolled back"),
        ({"ok": False, "noop": False, "errors": [
            {"code": "lifecycle_error", "message": "verify failed"},
            {"code": "hooks_drifted", "message": "hooks drifted"},
        ]}, "0|still failing (hooks_drifted): hooks drifted"),
        ({"ok": False, "noop": False, "errors": [
            {"code": "lifecycle_error", "message": "verify failed"},
        ]}, "0|still failing (lifecycle_error): verify failed"),
    ],
)
def test_remediation_summary_under_strict_mode(
    pwsh: str, tmp_path: Path, document: dict, expected: str,
) -> None:
    source = (SCRIPTS / "Remediate-Fix.ps1").read_text(encoding="utf-8")
    block = "$code = $run.ExitCode" + source.split("$code = $run.ExitCode", 1)[1].split("$line =", 1)[0]
    script = (
        "Set-StrictMode -Version 2.0\n"
        "$run = [pscustomobject]@{ ExitCode = [int]$env:DC_TEST_EXIT_CODE; "
        "StdOut = Get-Content -LiteralPath $env:DC_TEST_DOCUMENT -Raw }\n"
        + block + '\n[Console]::Out.WriteLine("$code|$summary")\n'
    )
    assert _run_script(pwsh, tmp_path, script, document) == expected


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"errors": [{"code": "lifecycle_busy", "message": "another run"}], "services": []}, "<null>"),
        ({"errors": [{"code": "lifecycle_error", "message": "verify failed"}], "services": [
            {"name": "DefenseClawGuardian", "required": True, "state": "stopped", "start_mode": "auto"},
        ]}, "verify failed (lifecycle_error): DefenseClawGuardian is stopped (start auto)"),
        ({"errors": [{"code": "hooks_drifted", "message": "hooks drifted"}], "warnings": [
            {"code": "telemetry_unreachable", "message": "otel down"},
        ], "services": []}, "verify failed (hooks_drifted): hooks drifted"),
        ({"errors": [
            {"code": "lifecycle_error", "message": "verify failed"},
            {"code": "hooks_drifted", "message": "hooks drifted"},
        ], "services": []}, "verify failed (hooks_drifted): hooks drifted"),
    ],
)
def test_detection_failure_under_strict_mode(
    pwsh: str, tmp_path: Path, document: dict, expected: str,
) -> None:
    source = (SCRIPTS / "Remediate-Detect.ps1").read_text(encoding="utf-8")
    function = "function Format-DefenseClawVerifyFailure" + source.split(
        "function Format-DefenseClawVerifyFailure", 1,
    )[1].split("\ntry {\n    $deployment", 1)[0]
    script = (
        "Set-StrictMode -Version 2.0\n" + function + "\n"
        "$failure = Format-DefenseClawVerifyFailure -Json "
        "(Get-Content -LiteralPath $env:DC_TEST_DOCUMENT -Raw)\n"
        "if ($null -eq $failure) { [Console]::Out.WriteLine('<null>') } "
        "else { [Console]::Out.WriteLine($failure) }\n"
    )
    assert _run_script(pwsh, tmp_path, script, document) == expected
