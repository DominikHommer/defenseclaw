# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Operator configuration recipes name the actual layout, scope and result."""

from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / 'docs-site/content/docs'


def flat(name):
    return ' '.join((DOCS / name).read_text().split())


@pytest.mark.parametrize('name', ['reference/configuration/index.mdx', 'reference/configuration/paths.mdx'])
def test_windows_layout_distinguishes_setup_from_powershell_install(name):
    text = flat(name)
    assert 'install.ps1' in text and '`.venv`' in text
    assert 'Setup package' in text and 'embedded runtime' in text


def test_status_json_modes_distinguish_user_and_enterprise_shapes():
    text = flat('reference/configuration/fail-modes.mdx')
    assert '`connectors[].fail_mode.effective`' in text
    assert '`name`' in text
    assert '`connectors.<id>.effective_hook_fail_mode`' in text
    assert 'standalone enterprise' in text


def test_ancestor_strictness_has_no_windows_only_qualifier():
    text = flat('enterprise/plan/threat-model.mdx')
    assert '`DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS` (Windows)' not in text
    assert 'strict ancestor checks on Linux, macOS and Windows' in text


@pytest.mark.parametrize('name', ['enterprise/identity/authentication.mdx', 'enterprise/identity/reference.mdx'])
def test_managed_windows_validation_names_the_machine_config(name):
    text = flat(name)
    assert 'config validate --config' in text
    assert 'C:\\ProgramData\\Cisco\\DefenseClaw\\etc\\config.yaml' in text
    assert 'ensure' in text


@pytest.mark.parametrize('name', ['enterprise/configure/reference.mdx', 'enterprise/configure/ai-defense-key.mdx'])
def test_disabled_ai_defense_reference_allows_key_removal(name):
    text = flat(name).split('Remove the key', 1)[1]
    assert 'enabled AI Defense inspection' in text
    assert 'disabled inspection does not prevent removal' in text


def test_manual_downgrade_regenerates_connectors_before_start():
    text = flat('appendix/migrate-v9.mdx').split('go back by hand:', 1)[1]
    regenerate = text.index('Regenerate every connector')
    start = text.index('Start the 0.8.x gateway')
    assert regenerate < start
    assert 'defenseclaw quickstart --connector claudecode --mode action' in text
    assert 'contract' in text[regenerate:start]
    assert 'fail mode' in text[regenerate:start]
