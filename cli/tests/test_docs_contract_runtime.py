# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Runtime coverage claims follow the installed connector and deployment mode."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


def flat(name):
    return " ".join((DOCS / name).read_text().split())


def test_kiro_v2_does_not_add_a_prompt_result():
    text = flat("reference/connectors/kiro.mdx")
    assert "CLI 2.x agent has no prompt hook" in text
    assert "each prompt carries two results" not in text
    assert "two `UserPromptSubmit` audit rows" not in text


def test_mcp_arguments_do_not_inherit_a_shell_path_rule():
    text = flat("how-to/guardrail/stop-a-secret-upload.mdx")
    assert "`PATH-SSH-KEY` needs a recognized read or copy operation" in text
    assert "MCP arguments alone does not trigger it" in text
    assert "A literal `id_rsa` path matches" not in text


@pytest.mark.parametrize("name", ["connectors/codex.mdx", "reference/connectors/codex.mdx", "how-to/guardrail/catch-prompt-injection.mdx"])
def test_codex_notify_is_scoped_to_secure_client(name):
    text = flat(name)
    assert "Secure Client" in text
    assert "Per-user and standalone" in text or "per-user and standalone" in text
    assert "do not register" in text
    if name == "reference/connectors/codex.mdx":
        assert '<Node id="notify"' not in text
        row = next(line for line in (DOCS / name).read_text().splitlines() if line.startswith("| Notify entry"))
        assert "Secure Client only" in row


def test_codex_notify_residual_has_the_same_scope():
    text = (DOCS / "enterprise/plan/threat-model.mdx").read_text()
    row = next(line for line in text.splitlines() if line.startswith("| **Codex passes each turn"))
    assert "Secure Client only" in row


def test_hermes_verification_discloses_snapshot_and_checks_current_files():
    text = flat("reference/connectors/hermes.mdx")
    assert "last reconcile" in text
    assert "enterprise hooks verify --json" in text
    assert "current hook files" in text
    assert "can still say `all` after hooks are removed" in text
    assert "#managed-verification" in flat("connectors/hermes.mdx")


def test_windows_hermes_gateway_failure_is_distinct_from_vendor_timeout():
    text = flat("appendix/windows-security-model.mdx")
    assert "Hermes never fails closed" not in text
    assert "Hermes blocks on DefenseClaw's valid block answer" in text
    assert "times out or cannot start" in text


def test_prompt_findings_follow_the_configured_threshold():
    text = flat("how-to/guardrail/catch-prompt-injection.mdx")
    assert "configured block threshold" in text
    assert "HIGH prompt findings can block" in text
    assert "A non-CRITICAL prompt finding is demoted" not in text


def test_site_description_qualifies_runtime_coverage():
    text = (ROOT / "docs-site/lib/site.ts").read_text()
    assert "Inspect the runtime events each connector sends." in text
    assert "Inspect prompts, completions, and tool calls at runtime." not in text
