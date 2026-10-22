# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0350: release-floor refusals, recovery and package coverage limits."""

import re
import shlex
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs-site/content/docs"
REFERENCE = "enterprise/operate/reference.mdx"
TROUBLESHOOTING = "troubleshooting/enterprise/index.mdx"
PROCEDURE_LINK = "/docs/enterprise/operate/reference#lower-the-release-floor"


def _flat(page: str) -> str:
    return " ".join((DOCS / page).read_text(encoding="utf-8").split())


def _section(page: str, heading: str) -> str:
    text = (DOCS / page).read_text(encoding="utf-8")
    start = text.index(heading)
    rest = text[start + len(heading) :]
    end = re.search(r"^#{1,3} ", rest, flags=re.MULTILINE)
    return " ".join((rest[: end.start()] if end else rest).split())


def _go_source(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "page",
    ["enterprise/operate/lifecycle.mdx", TROUBLESHOOTING],
)
def test_gap_0350_release_floor_and_recovery_are_documented(page: str) -> None:
    text = _flat(page)
    assert "product_floor_refused" in text
    assert "min_product_version" in text
    assert "lower `--min-product-version`" in text
    # The recovery points at a published procedure, not at nothing.
    assert PROCEDURE_LINK in text


def test_gap_0350_package_floor_limits_include_old_scripts_and_windows() -> None:
    text = _section(REFERENCE, "### Release floor limits")
    for fact in ("older than 1.0.4", "`rpm`", "`dnf`", "`dpkg -i`", "macOS Installer", "Windows Setup"):
        assert fact in text
    assert "apt hook" in text
    assert "retained floor checker" in text
    assert "release-floor-limits" in _flat("appendix/upgrade-from-0-8.mdx")


def test_release_floor_scope_matches_bundle_floor_applies() -> None:
    """The docs name exactly the runs bundleFloorApplies checks, and its exceptions."""
    text = _section(REFERENCE, "### Release floor limits")
    # Promises the runtime does not keep (loop round 1 finding).
    assert "including a reinstall or repair" not in text
    assert "a check that cannot prove the floor refuses" not in text
    # The checked runs (internal/enterpriseunix/bundle_product_floor.go).
    source = _go_source("internal/enterpriseunix/bundle_product_floor.go")
    assert 'record == nil || version != strings.TrimPrefix(strings.TrimSpace(record.ProductVersion), "v") ||' in source
    assert "!enterprisebundle.IsReleaseVersion(version)" in source
    for fact in (
        "no deployment record",
        "`uninstall --keep-state`",
        "the version changes, up or down",
        "the version is not a release",
        "does not check the floor again",
    ):
        assert fact in text, fact
    # A damaged bundle on a same-release run is a warning, not a refusal.
    assert "`bundle_state_unreadable`" in text
    assert "keeps the config the last deployment committed" in text
    assert (
        'r.AddWarning(codeBundleStateUnreadable, "cannot read the current policy bundle, so the config the last deployment committed is kept'
        in _go_source("internal/enterpriseunix/bundleapply.go")
    )
    # A failed retained-checker copy leaves the next preinstall without a check.
    assert "`floor_checker_not_kept`" in text
    assert "after the files are in place" in text
    assert "r.AddWarning(codeFloorCheckerNotKept," in _go_source("internal/enterpriseunix/lifecycle.go")


def test_troubleshooting_lists_floor_codes_in_the_right_tables() -> None:
    text = (DOCS / TROUBLESHOOTING).read_text(encoding="utf-8")
    errors = text[text.index("## Lifecycle error codes") : text.index("### Warnings")]
    warnings = text[text.index("### Warnings") : text.index("## Kernel sensor warnings")]
    # product_floor_refused is an error (exit 1, or 3 from floor-check), with a Fix column.
    [row] = [line for line in errors.splitlines() if line.startswith("| `product_floor_refused` |")]
    assert row.count(" | ") == 3, row
    assert PROCEDURE_LINK in row
    assert "product_floor_refused" not in warnings
    for code in ("bundle_state_unreadable", "floor_checker_not_kept"):
        [row] = [line for line in warnings.splitlines() if line.startswith(f"| `{code}` |")]
        assert row.count(" | ") == 2, row


def _procedure_commands() -> list[list[str]]:
    text = (DOCS / REFERENCE).read_text(encoding="utf-8")
    start = text.index("### Lower the release floor")
    end = text.index("\n### ", start + 1)
    commands = []
    for fence in re.findall(r"```bash\n(.*?)```", text[start:end], flags=re.DOTALL):
        commands.append(shlex.split(" ".join(fence.replace("\\\n", " ").split())))
    return commands


def _cobra_flags(path: str) -> set[str]:
    return set(re.findall(r'\.(?:String|Bool|Uint64|StringSlice)Var\([^,]+, "([a-z-]+)"', _go_source(path)))


def test_lower_the_release_floor_procedure_uses_real_commands_and_flags() -> None:
    commands = _procedure_commands()
    verbs = [cmd[cmd.index("bundle") + 1] for cmd in commands]
    assert verbs == ["sign", "verify", "apply", "floor-check"]
    sources = {
        "sign": "internal/cli/enterprise_bundle.go",
        "verify": "internal/cli/enterprise_bundle.go",
        "apply": "internal/cli/enterprise_bundle_apply.go",
        "floor-check": "internal/cli/enterprise_bundle_floor.go",
    }
    for cmd, verb in zip(commands, verbs):
        assert f'Use:          "{verb}"' in _go_source(sources[verb]) or f'Use:   "{verb}"' in _go_source(sources[verb])
        known = _cobra_flags(sources[verb])
        used = {arg[2:] for arg in cmd if arg.startswith("--")}
        assert used <= known, (verb, used - known)
        if verb != "sign":
            assert cmd[0] == "sudo", cmd
            assert cmd[1] == "/opt/defenseclaw/bin/defenseclaw-gateway", cmd
    sign = commands[0]
    assert "--min-product-version" in sign and "--version" in sign
    # The documented exit codes are the command's.
    assert "const bundleFloorRefusedExit = 3" in _go_source("internal/cli/enterprise_bundle_floor.go")
    assert "Exit `0` allows it; exit `3` refuses it" in _section(REFERENCE, "### Lower the release floor")
