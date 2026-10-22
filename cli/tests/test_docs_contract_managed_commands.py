# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Managed package commands must not inherit the per-user CLI's promises."""

from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / "docs-site/content/docs"


@pytest.mark.parametrize(
    ("page", "facts", "obsolete"),
    [
        (
            "reference/sandboxes/cli.mdx",
            ("per-user feed installer", "standalone managed Linux and macOS"),
            ("a managed host, where sandboxes are not supported",),
        ),
        (
            "enterprise/plan/concepts.mdx",
            ("manifest` on Linux, macOS and Windows",),
            ("manifest` on Linux and macOS",),
        ),
        (
            "reference/commands/cli.mdx",
            (
                "`init` and `quickstart` are not shipped",
                "`doctor` prints administrator guidance and exits `1`",
                "`show` and `verify` take `--json`",
                "`export` prints the selected vendor format",
                "read the installed managed config and runtime automatically",
                "defenseclaw tool status <name> [--connector X]",
            ),
            ("All three take `--json`", "defenseclaw tool list/status"),
        ),
        (
            "reference/configuration/env-vars.mdx",
            ("On managed Linux and macOS", "enterprise macos status"),
            (),
        ),
        (
            "reference/commands/tui.mdx",
            ("Managed packages ship no TUI", "enterprise macos status"),
            ("The editor still opens",),
        ),
    ],
)
def test_managed_package_command_scope(page, facts, obsolete):
    text = " ".join((DOCS / page).read_text(encoding="utf-8").split())
    for fact in facts:
        assert fact in text, (page, fact)
    for claim in obsolete:
        assert claim not in text, (page, claim)


@pytest.mark.parametrize("page", ["enterprise/mdm/index.mdx", "enterprise/mdm/intune/macos.mdx"])
def test_mdm_live_delivery_names_the_test_build(page):
    text = (DOCS / page).read_text()
    assert "`9.9.9`" in text
    assert "f9ed814b1" in text
    assert "test build" in text


def test_mdm_invalid_candidate_code_is_consistent():
    for page in (
        "enterprise/mdm/index.mdx",
        "enterprise/mdm/reference.mdx",
        "enterprise/mdm/workspace-one.mdx",
        "enterprise/mdm/configmgr.mdx",
        "enterprise/mdm/intune/tenant-reference.mdx",
    ):
        text = (DOCS / page).read_text()
        if page.endswith("workspace-one.mdx"):
            text = text.split("## macOS", 1)[0]
        assert "invalid_arguments" in text, page
        assert "1639" in text, page
