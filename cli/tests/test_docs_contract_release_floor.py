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

from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / "docs-site/content/docs"


def _flat(page: str) -> str:
    return " ".join((DOCS / page).read_text(encoding="utf-8").split())


@pytest.mark.parametrize(
    "page",
    ["enterprise/operate/lifecycle.mdx", "troubleshooting/enterprise/index.mdx"],
)
def test_gap_0350_release_floor_and_recovery_are_documented(page: str) -> None:
    text = _flat(page)
    assert "product_floor_refused" in text
    assert "min_product_version" in text
    assert "lower `--min-product-version`" in text


def test_gap_0350_package_floor_limits_include_old_scripts_and_windows() -> None:
    text = _flat("enterprise/operate/reference.mdx")
    assert "### Release floor limits" in text
    for fact in ("older than 1.0.4", "`rpm`", "`dnf`", "`dpkg -i`", "macOS Installer", "Windows Setup"):
        assert fact in text
    assert "apt hook" in text
    assert "retained floor checker" in text
    assert "release-floor-limits" in _flat("appendix/upgrade-from-0-8.mdx")
