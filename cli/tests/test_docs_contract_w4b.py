# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Operator contracts for the 1.0.4 wave 4b documentation gaps."""

from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / "docs-site/content/docs"


def _flat(page: str) -> str:
    return " ".join((DOCS / page).read_text(encoding="utf-8").split())


def test_gap_0355_outage_examples_include_the_managed_service_refusal() -> None:
    text = _flat("enterprise/configure/foreign-hook-guard.mdx")
    assert "enterprise_foreign_hook_blocked" in text
    assert "enterprise_managed_gateway_not_running" in text
    assert "Claude Code" in text and "service is not running" in text
    assert "Both refusals block the call" in text


def test_gap_0373_otlp_guide_does_not_promise_an_unsupported_write() -> None:
    text = _flat("how-to/observability/send-to-an-otlp-collector.mdx")
    assert "`--write-probe` is not supported for OTLP" in text
    assert "does not prove delivery" in text
    assert "collector" in text and "event ID" in text
    assert "Add `--write-probe` to send" not in text
    assert "OTLP supports the handshake only" in _flat("reference/commands/cli.mdx")
    runbooks = _flat("reference/observability/index.mdx")
    assert runbooks.count("OTLP supports the handshake only") == 2


@pytest.mark.parametrize(
    "page",
    ["enterprise/plan/threat-model.mdx", "enterprise/configure/reference.mdx"],
)
def test_gap_0379_managed_guarantee_distinguishes_admin_outage_policy_from_peer_trust(page: str) -> None:
    text = _flat(page)
    assert "administrator" in text and "`hook_fail_mode: open`" in text
    assert "outage" in text
    assert "/docs/reference/configuration/fail-modes" in text
    assert "`defenseclaw-hook` always fails closed" not in text
    assert "does not override fail-closed gateway peer verification when the gateway is down" not in text


@pytest.mark.parametrize("page", ["enterprise/configure/ai-defense-key.mdx", "enterprise/configure/reference.mdx"])
def test_gap_0383_removal_names_the_enabled_ai_defense_reference(page: str) -> None:
    text = _flat(page).split("## Remove the key" if page.endswith("ai-defense-key.mdx") else "### Remove the key", 1)[1]
    assert "enabled AI Defense" in text
    assert "disabled AI Defense" in text
    assert "Removal refuses a credential the installed config still names" not in text
