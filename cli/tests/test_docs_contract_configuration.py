# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Operator configuration recipes name the actual layout, scope and result."""

import json
import re
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
    text = flat('appendix/migrate-v9.mdx').split('go back by hand', 1)[1].split('If you do not have a matching', 1)[0]
    regenerate = text.index('Regenerate every connector')
    start = text.index('Start the 0.8.x gateway')
    assert regenerate < start
    assert "matching pre-upgrade `.env`" in text
    assert 'defenseclaw agent discover --refresh' in text[regenerate:start]
    assert 'contract lock' in text[start:]
    assert 'fail mode' in text[start:]


def test_manual_downgrade_keeps_the_restored_config():
    # 0.8.x quickstart and init keep only the named connector and reset the
    # scanner mode and the judge, so they must not run on a restored config.
    raw = (DOCS / 'appendix/migrate-v9.mdx').read_text()
    section = raw.split('go back by hand', 1)[1].split('If you do not have a matching', 1)[0]
    commands = ' '.join(re.findall(r'```(?:bash|sh|powershell)?\n(.*?)```', section, re.S))
    assert 'agent discover --refresh' in commands
    assert 'quickstart' not in commands and 'defenseclaw init' not in commands
    text = ' '.join(section.split())
    assert 'Do not run `quickstart` or `init` here' in text
    assert 'scanner mode' in text and 'judge' in text
    assert 'does not change it' in text
    assert 'still the restored file' in text


def test_manual_downgrade_sends_windows_codex_to_rollback():
    text = flat('appendix/migrate-v9.mdx').split('go back by hand', 1)[1][:600]
    assert 'Windows with the Codex connector' in text and '`defenseclaw rollback`' in text


def test_windows_enrollment_wait_starts_after_agent_first_start():
    text = flat("enterprise/configure/enrollment.mdx")
    assert "account is signed in and the agent is installed" in text
    assert "Claude Code must also start once" in text
    assert "five-minute wait starts then" in text


def test_windows_setup_result_does_not_promise_a_changes_list():
    text = flat("enterprise/operate/reference.mdx")
    assert "On Linux and macOS the result's `changes` list" in text
    assert "Windows Setup results report `policy` and the installed version but no `changes` list" in text


ENTERPRISE = DOCS / 'enterprise'
BUNDLE_LINK = '/docs/enterprise/mdm/signed-bundles'
# A step, row or heading that tells an administrator how to change the config.
CONFIG_CHANGE_RECIPE = re.compile(
    r'^#{2,4} [^\n]*[Cc]hange the config'
    r'|\*\*(?:Upgrade or |Upgrade, )?[Cc]hange the config'
    r'|^\| Change the config'
    r'|config-only change'
    r'|change the config only through',
    re.MULTILINE,
)


def _config_change_pages():
    for page in sorted(ENTERPRISE.rglob('*.mdx')):
        rel = page.relative_to(DOCS).as_posix()
        # Secure Client computers do not take signed bundles.
        if 'secure-client' in rel or rel == 'enterprise/mdm/signed-bundles.mdx':
            continue
        if CONFIG_CHANGE_RECIPE.search(page.read_text()):
            yield rel


def test_signed_bundle_page_covers_the_lifecycle():
    text = flat('enterprise/mdm/signed-bundles.mdx')
    for heading in ('## Bundle mode', '## Sign and check a bundle', '## First deployment',
                    '## Roll out a new bundle', '### Upgrade the product in bundle mode', '## Check it worked'):
        assert heading in text
    assert 'bundle-anchors.json' in text and 'bundle_required' in text
    assert 'enterprise bundle verify' in text and 'enterprise bundle status --json' in text
    assert '-BundlePath' in text and '-TrustAnchorPath' in text and 'detect-bundle.ps1' in text
    assert 'dc_inline_bundle' in text and 'dc_inline_trust_anchors' in text
    assert '`applied` is `true`' in text and 'last_refusal' in text
    assert 'Secure Client computers do not take bundles' in text


def test_signed_bundle_page_is_in_the_mdm_navigation():
    pages = json.loads((ENTERPRISE / 'mdm/meta.json').read_text())['pages']
    assert 'signed-bundles' in pages


@pytest.mark.parametrize('name', [
    'enterprise/mdm/index.mdx',
    'enterprise/mdm/intune/windows.mdx',
    'enterprise/mdm/intune/linux.mdx',
    'enterprise/mdm/intune/macos.mdx',
    'enterprise/mdm/intune/windows-reference.mdx',
])
def test_mdm_pages_link_the_signed_bundle_page(name):
    assert BUNDLE_LINK in flat(name)


def test_config_change_recipes_are_found():
    found = set(_config_change_pages())
    for name in ('enterprise/mdm/intune/windows.mdx', 'enterprise/mdm/intune/linux.mdx',
                 'enterprise/mdm/intune/macos.mdx', 'enterprise/mdm/reference.mdx',
                 'enterprise/operate/lifecycle.mdx', 'enterprise/mdm/configmgr.mdx',
                 'enterprise/mdm/jamf.mdx', 'enterprise/mdm/kandji.mdx'):
        assert name in found


@pytest.mark.parametrize('name', sorted(set(_config_change_pages()) | {
    'enterprise/configure/configuration.mdx',
    'enterprise/operate/reference.mdx',
}))
def test_config_change_recipes_are_qualified_for_bundle_mode(name):
    text = flat(name)
    assert "bundle mode" in text.lower(), name
    assert BUNDLE_LINK in text, name


def test_windows_bundle_mode_upgrade_leaves_the_config_out():
    text = flat('enterprise/mdm/intune/windows.mdx').split('**Upgrade.**', 1)[1].split('**Roll back.**', 1)[0]
    assert 'without `-ConfigPath`' in text
    row = next(line for line in (DOCS / 'enterprise/mdm/intune/windows-reference.mdx').read_text().splitlines()
               if line.startswith('| `-ConfigPath`'))
    assert 'bundle_required' in row


WRAPPERS = ('packaging/mdm/linux/defenseclaw-enterprise.sh', 'packaging/mdm/macos/defenseclaw-enterprise.sh')
# Words that promise a refused run left the device as it was.
NO_CHANGE_CLAIM = re.compile(
    r'nothing (?:else )?(?:changes|changed|is changed|was changed|is installed|was installed|is applied|was applied|is stored)'
    r'|changes nothing|leaves the device (?:as it was|unchanged)|device is unchanged',
    re.IGNORECASE,
)


def _doc_blocks(text):
    # A paragraph, a list item or a table row.
    return re.split(r'\n\s*\n|\n(?=\s*(?:[-*]|\d+\.|\|) )', text)


@pytest.mark.parametrize('wrapper', WRAPPERS)
def test_unix_wrapper_runs_package_and_credential_before_the_bundle_mode_check(wrapper):
    # The page discloses this order; if the wrapper ever refuses first, the
    # disclosure must change with it.
    main = (DOCS.parents[2] / wrapper).read_text().split('\ndc_main() {', 1)[1]
    package = main.index('dc_install_package')
    secret = main.index('dc_store_secret "$gateway"')
    ensure = main.index('"--config=$ensure_config"')
    assert package < ensure and secret < ensure


def test_bundle_required_refusal_discloses_the_wrapper_steps_that_already_ran():
    text = (DOCS / 'enterprise/mdm/signed-bundles.mdx').read_text()
    section = ' '.join(text.split('## Bundle mode', 1)[1].split('\n## ', 1)[0].split())
    assert 'the config is not applied' in section
    assert 'deb, rpm or pkg package (`--source`) is installed' in section
    assert 'a credential (`--secret-name`) is stored' in section


def test_no_page_promises_a_bundle_required_refusal_changes_nothing():
    offenders = []
    for page in sorted(DOCS.rglob('*.mdx')):
        for block in _doc_blocks(page.read_text()):
            if 'bundle_required' in block and NO_CHANGE_CLAIM.search(block):
                offenders.append(f'{page.relative_to(DOCS)}: {" ".join(block.split())[:160]}')
    assert not offenders, '\n'.join(offenders)
