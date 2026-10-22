# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Connector recipes must work with the single connector they set up."""

from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / "docs-site/content/docs"
PAGES = sorted(p for p in (DOCS / "connectors").glob("*.mdx") if "## Turn it off" in p.read_text() and "guardrail disable" in p.read_text())


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.stem)
def test_turn_off_explains_single_and_multi_connector_scope(page):
    section = page.read_text().split("## Turn it off", 1)[1].split("\n## ", 1)[0]
    assert "single-connector" in section
    assert "defenseclaw guardrail disable --yes" in section
    assert "`defenseclaw guardrail enable`" in section
    assert "multi-connector" in section
    assert f"--connector {page.stem}" in section


def test_hitl_selector_requires_multiple_connectors():
    text = (DOCS / "how-to/guardrail/ask-before-risky-calls.mdx").read_text()
    assert "multi-connector install" in text
    assert "single connector, omit `--connector`" in text
