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
OPERATOR_CONTRACT = "packaging/mdm/contract/management-agent.md"


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


def _contract_section(heading: str) -> str:
    text = (REPO / OPERATOR_CONTRACT).read_text(encoding="utf-8")
    start = text.index(heading)
    end = text.index("\n## ", start + 1)
    return text[start:end]


def _cobra_flags(path: str) -> set[str]:
    return set(re.findall(r'\.(?:String|Bool|Uint64|StringSlice)Var\([^,]+, "([a-z-]+)"', _go_source(path)))


# Owner hold: signed-bundle procedures stay off the public site until the sync
# service ships. Public pages may name the outcome, never the commands.
_BUNDLE_PROCEDURE = re.compile(r"\bbundle\s+(?:sign|apply|floor-check)\b")


def test_public_lower_the_release_floor_states_the_outcome_only() -> None:
    text = (DOCS / REFERENCE).read_text(encoding="utf-8")
    start = text.index("### Lower the release floor")
    section = text[start : text.index("\n### ", start + 1)]
    assert "```" not in section
    assert not _BUNDLE_PROCEDURE.search(section), section
    flat = " ".join(section.split())
    assert "lower floor, or with no floor" in flat
    assert "The rollback marker and `--allow-downgrade` do not lift the floor" in flat
    assert "/docs/enterprise/operate/lifecycle#roll-back" in flat


def test_no_public_page_carries_a_signed_bundle_procedure() -> None:
    hits = []
    for page in sorted(DOCS.rglob("*.mdx")):
        for number, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
            if _BUNDLE_PROCEDURE.search(line):
                hits.append(f"{page.relative_to(DOCS)}:{number}: {line.strip()}")
    assert not hits, hits


def test_operator_contract_lowers_the_floor_with_real_commands_and_flags() -> None:
    section = _contract_section("### 5.3 Lower the release floor")
    flat = " ".join(section.split())
    assert "`product_floor_refused`" in flat
    assert "DefenseClaw 1.0.4 and later refuse to install a release below" in flat
    assert "do not lift it" in flat
    assert "Deliver it as in 5.2" in flat
    fences = re.findall(r"```sh\n(.*?)```", section, flags=re.DOTALL)
    commands = [shlex.split(" ".join(f.replace("\\\n", " ").split())) for f in fences]
    assert [cmd[1:4] for cmd in commands] == [["enterprise", "bundle", "sign"], ["enterprise", "bundle", "floor-check"]]
    sign, floor = commands
    assert sign[0] == "defenseclaw-gateway" and floor[0] == "$GW", commands
    sources = {"sign": "internal/cli/enterprise_bundle.go", "floor-check": "internal/cli/enterprise_bundle_floor.go"}
    for cmd in commands:
        source = _go_source(sources[cmd[3]])
        assert f'Use:          "{cmd[3]}"' in source or f'Use:   "{cmd[3]}"' in source
        used = {arg[2:] for arg in cmd if arg.startswith("--")}
        assert used <= _cobra_flags(sources[cmd[3]]), (cmd[3], used - _cobra_flags(sources[cmd[3]]))
    assert {"version", "min-product-version"} <= {arg[2:] for arg in sign if arg.startswith("--")}
    # The exit codes the contract names are the command's, and older packages are not checked.
    assert "exit `0` allows it, exit `3` refuses it" in flat
    assert "Older packages do not check the floor in any script and can complete below it" in flat
    assert "const bundleFloorRefusedExit = 3" in _go_source("internal/cli/enterprise_bundle_floor.go")


# Package scripts that run the floor check: a gateway without the marker is one
# from before 1.0.4, which has no check of its own.
_FLOOR_SCRIPTS = (
    "packaging/linux/preinstall.sh",
    "packaging/linux/apt-downgrade-guard.sh",
    "scripts/build-macos-enterprise-pkg.sh",
)


def _floor_doc_texts() -> dict[str, str]:
    texts = {
        page.relative_to(DOCS).as_posix(): _flat(page.relative_to(DOCS).as_posix()) for page in DOCS.rglob("*.mdx")
    }
    texts[OPERATOR_CONTRACT] = " ".join((REPO / OPERATOR_CONTRACT).read_text(encoding="utf-8").split())
    return texts


def _sentences(text: str) -> list[str]:
    return re.split(r"(?<=\.)\s+", text)


def _says_older_packages_complete(text: str) -> bool:
    return any(
        ("older than 1.0.4" in s or "Older packages" in s) and re.search(r"\bcomplete[s]? below\b", s)
        for s in _sentences(text)
    )


def test_package_floor_check_is_only_in_1_0_4_and_later_scripts() -> None:
    """Ground truth for the docs below: the scripts ask only a gateway with the marker."""
    for script in _FLOOR_SCRIPTS:
        source = _go_source(script)
        assert "floor_check_marker=defenseclaw-package-floor-check/1" in source, script
        assert "# a gateway before 1.0.4: it has no floor check" in source, script
    assert "defenseclaw-package-floor-check/1" in _go_source("internal/cli/enterprise_bundle_floor.go")


def test_postinstall_floor_refusal_is_promised_only_for_packages_with_the_check() -> None:
    """A package older than 1.0.4 has no floor check in its preinstall, postinstall
    or ensure, so no page may say a postinstall refuses a release below the floor
    without naming 1.0.4 or later packages (loop round 3 finding)."""
    hits = []
    for page, text in _floor_doc_texts().items():
        for sentence in _sentences(text):
            if "postinstall" not in sentence or "refuse" not in sentence:
                continue
            if "floor" not in sentence:
                continue
            if "1.0.4 or later" not in sentence and "1.0.4 and later" not in sentence:
                hits.append(f"{page}: {sentence}")
    assert not hits, hits
    for page, text in _floor_doc_texts().items():
        # An unscoped "the device never goes below the floor" is the same promise.
        assert "oldest release you can install" not in text, page
        assert "a device does not install a release below" not in text, page
        assert "only its postinstall `ensure` refuses" not in text, page


def test_floor_docs_say_an_older_package_completes_below_the_floor() -> None:
    pages = {page: text for page, text in _floor_doc_texts().items() if "`floor_checker_not_kept`" in text}
    assert {REFERENCE, TROUBLESHOOTING, OPERATOR_CONTRACT} <= set(pages), sorted(pages)
    for page, text in pages.items():
        assert _says_older_packages_complete(text), page
    # The roll-back section, where the floor is introduced, says it too.
    assert _says_older_packages_complete(_section("enterprise/operate/lifecycle.mdx", "## Roll back"))
    assert _says_older_packages_complete(_section(REFERENCE, "### Release floor limits"))
    assert _says_older_packages_complete(" ".join(_contract_section("### 5.3 Lower the release floor").split()))
    [row] = [
        line
        for line in (DOCS / TROUBLESHOOTING).read_text(encoding="utf-8").splitlines()
        if line.startswith("| `floor_checker_not_kept` |")
    ]
    assert _says_older_packages_complete(row), row
