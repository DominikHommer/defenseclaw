import json
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "packaging/mdm/linux/defenseclaw-enterprise.sh"


def function(source: str, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}$", source, re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group()


def test_full_staging_folder_is_not_reported_as_bad_archive(tmp_path: Path) -> None:
    source = WRAPPER.read_text(encoding="utf-8")
    helpers = "\n".join(function(source, name) for name in (
        "dc_json_escape", "dc_log", "dc_fail_result", "dc_extract_payload"
    ))
    fake = tmp_path / "tar"
    fake.write_text(
        "#!/bin/sh\ncase \"$1\" in -tzf) echo defenseclaw-gateway;; "
        "-xzf) echo 'No space left on device' >&2; exit 2;; esac\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    stage = tmp_path / "stage"
    stage.mkdir()
    script = (
        "DC_ACTION=ensure; DC_SCRIPT_OS=linux; DC_EXIT_FAILURE=1; DC_LOG=''; "
        f"DC_STAGE='{stage}'; DC_STAGED_SOURCE='{tmp_path / 'payload.tar.gz'}'\n"
        + helpers + "\ndc_extract_payload\n"
    )
    result = subprocess.run(["sh", "-c", script], env={"PATH": f"{tmp_path}:{os.environ['PATH']}"},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 1, result.stderr
    error = json.loads(result.stdout)["errors"][0]
    assert error["code"] == "mdm_staging_full"
    assert str(stage) in error["message"] and "full" in error["message"]
