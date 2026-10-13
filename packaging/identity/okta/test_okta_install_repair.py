import os
import re
import subprocess
from pathlib import Path


KIT = Path(__file__).parent
INSTALLER = KIT / "install-sssd-okta.sh"


def function(source: str, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}$", source, re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group()


def test_identical_sssd_config_repairs_unsafe_mode(tmp_path: Path) -> None:
    config = tmp_path / "sssd.conf"
    rendered = tmp_path / "rendered.conf"
    config.write_text("# managed fixture\n", encoding="ascii")
    rendered.write_bytes(config.read_bytes())
    config.chmod(0o644)
    calls = tmp_path / "calls"
    for name, body in {
        "chown": 'echo "chown $*" >>"$CALL_LOG"',
        "chmod": 'echo "chmod $*" >>"$CALL_LOG"; /bin/chmod "$@"',
        "stat": 'echo "stat $*" >>"$CALL_LOG"; /usr/bin/stat "$@"',
        "systemctl": 'echo "systemctl $*" >>"$CALL_LOG"',
        "sshd": 'echo "sshd $*" >>"$CALL_LOG"',
    }.items():
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body + "\n", encoding="ascii")
        path.chmod(0o755)
    source = INSTALLER.read_text(encoding="utf-8")
    script = (
        f"set -euo pipefail\nCONF='{config}'\nDRY_RUN=0\nCHANGED=0\nCONF_CHANGED=0\n"
        "log() { :; }\nfail() { exit \"$1\"; }\n"
        + function(source, "install_conf") + f"\ninstall_conf '{rendered}'\n"
    )
    result = subprocess.run(["bash", "-c", script], env={"PATH": f"{tmp_path}:{os.environ['PATH']}", "CALL_LOG": str(calls)},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert config.stat().st_mode & 0o777 == 0o600
    assert "chown root:root" in calls.read_text()
