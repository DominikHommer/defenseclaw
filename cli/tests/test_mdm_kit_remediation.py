import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "packaging/mdm/intune/windows"


def test_remediation_names_problem_and_repair_from_lifecycle_result() -> None:
    source = (SCRIPTS / "Remediate-Fix.ps1").read_text(encoding="utf-8")
    summary = source.split("$code = $run.ExitCode", 1)[1].split("$line =", 1)[0]
    assert "$repairChanges = @($document.changes)" in summary
    assert "$specificProblem =" in summary
    pwsh = os.environ.get("DEFENSECLAW_TEST_PWSH") or shutil.which("pwsh") or shutil.which("pwsh.exe")
    if not pwsh:
        return
    cases = [
        ('{"ok":true,"noop":true,"errors":[],"warnings":[{"code":"service_stopped","message":"guardian was stopped"}],"changes":["started guardian"]}',
         "service_stopped", "started guardian"),
        ('{"ok":false,"noop":false,"errors":[{"code":"lifecycle_error","message":"verify failed"}],"warnings":[{"code":"service_stopped","message":"guardian was stopped"}],"changes":[]}',
         "service_stopped", "guardian was stopped"),
    ]
    for document, problem, repair in cases:
        script = f"$run = @{{ ExitCode = 0; StdOut = '{document}' }}\n" + "$code = $run.ExitCode" + summary + "\nWrite-Output $summary\n"
        result = subprocess.run([pwsh, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert problem in result.stdout and repair in result.stdout
        assert "already healthy" not in result.stdout


def test_remediation_detect_prefers_specific_problem_to_lifecycle_error() -> None:
    source = (SCRIPTS / "Remediate-Detect.ps1").read_text(encoding="utf-8")
    formatter = source.split("function Format-DefenseClawVerifyFailure", 1)[1].split("\ntry {\n    $deployment", 1)[0]
    assert "specific" in formatter and "lifecycle_error" in formatter
    pwsh = os.environ.get("DEFENSECLAW_TEST_PWSH") or shutil.which("pwsh") or shutil.which("pwsh.exe")
    if not pwsh:
        return
    document = '{"errors":[{"code":"lifecycle_error","message":"verify failed"}],"warnings":[{"code":"service_stopped","message":"guardian was stopped"}],"services":[]}'
    script = "function Format-DefenseClawVerifyFailure" + formatter + f"\nFormat-DefenseClawVerifyFailure -Json '{document}'\n"
    result = subprocess.run([pwsh, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "service_stopped" in result.stdout and "guardian was stopped" in result.stdout
