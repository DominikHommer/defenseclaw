import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

// Docs claims that must match what the product does. Page checks collapse
// whitespace so a reflowed paragraph still matches; source checks tie the
// wording to the CLI and Go paths that implement it.

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');
const hookConnectors = [
  { id: 'claudecode', command: 'claude-code', name: 'Claude Code' },
  { id: 'codex', command: 'codex', name: 'Codex' },
  { id: 'cursor', command: 'cursor', name: 'Cursor' },
  { id: 'devin', command: 'devin', name: 'Devin' },
  { id: 'copilot', command: 'copilot', name: 'Copilot' },
  { id: 'hermes', command: 'hermes', name: 'Hermes' },
  { id: 'antigravity', command: 'antigravity', name: 'Antigravity' },
  { id: 'opencode', command: 'opencode', name: 'OpenCode' },
  { id: 'kiro', command: 'kiro', name: 'Kiro' },
  { id: 'amp', command: 'amp', name: 'Amp' },
] as const;

function page(name: string): string {
  return readFileSync(join(site, 'content/docs', name), 'utf8').split(/\s+/).join(' ');
}

function source(name: string): string {
  return readFileSync(join(repo, name), 'utf8');
}

describe('Cursor observe outage mode', () => {
  it('keeps the rendered hook closed unless the config explicitly opens it', () => {
    const hooks = source('internal/gateway/connector/subprocess.go');
    const outage = hooks.split('func OutageHookFailMode(')[1]?.split('\n}')[0] ?? '';
    assert.match(outage, /perUserCursorRender\(opts, conn\)/);
    assert.match(outage, /!strings\.EqualFold\(strings\.TrimSpace\(opts\.ConfiguredHookFailMode\), "open"\)/);
    assert.match(outage, /return "closed"/);
    assert.match(hooks, /func renderedHookFailMode\([\s\S]*?OutageHookFailMode\(opts, conn\)/);
    const failModes = page('reference/configuration/fail-modes.mdx').split('## Controls')[0] ?? '';
    const cursor = page('reference/connectors/cursor.mdx').split('## Fail mode')[1]?.split('## Limits')[0] ?? '';
    assert.match(failModes, /Per-user Cursor in observe mode.{0,100}blocks supported events during a gateway outage by default/i);
    assert.match(cursor, /observe mode.{0,100}blocks supported events on a gateway outage by default/i);
    const coverage = page('appendix/coverage-by-layer.mdx');
    assert.match(coverage, /Per-user Cursor in observe mode.{0,130}running hook blocks supported events during a gateway outage/i);
    assert.match(page('features/guardrail.mdx'), /Per-user Cursor in observe mode still blocks a supported event during a gateway outage/i);
    assert.match(page('reference/commands/installer.mdx'), /Per-user Cursor observe also blocks supported events during a gateway outage/i);
    const managedRegistration = source('internal/gateway/connector/cursor_enterprise_hooks.go');
    assert.match(managedRegistration, /"failClosed": mode == "closed"/);
    assert.match(page('reference/connectors/cursor.mdx'), /failClosed` value follows the administrator's resolved fail mode/i);
    assert.ok(!/per-user Cursor in observe mode fails open/i.test(failModes));
  });
});

describe('Intune base config versus the signed bundle', () => {
  it('names exactly the blocks the packager compares', () => {
    const packager = readFileSync(
      join(repo, 'packaging/mdm/intune/windows/New-DefenseClawIntunePackage.ps1'),
      'utf8',
    );
    assert.ok(packager.includes('No other key is compared'), 'packager no longer says what it compares');
    const list = /foreach \(\$key in ((?:'[a-z_]+'(?:, )?)+)\)/.exec(packager);
    assert.ok(list, 'packager hook-block key list not found');
    const compared = [...list[1].matchAll(/'([a-z_]+)'/g)].map((match) => match[1]);
    assert.ok(compared.length > 0);
    const reference = readFileSync(join(site, 'content/docs/enterprise/mdm/intune/windows-reference.mdx'), 'utf8');
    const row = reference.split('\n').find((line) => line.startsWith('| `-BaseConfigPath` |'));
    assert.ok(row, 'windows-reference has no -BaseConfigPath row');
    assert.ok(row.includes('No other setting is compared'), 'the -BaseConfigPath row does not say nothing else is compared');
    for (const key of ['guardrail', ...compared]) {
      assert.ok(row.includes(`\`${key}:\``), `the -BaseConfigPath row does not name the compared ${key}: block`);
    }
  });
});

describe('fail mode of Copilot CLI and Antigravity hooks', () => {
  it('says the hooks follow a closed fail mode', () => {
    const failModes = page('reference/configuration/fail-modes.mdx');
    assert.ok(!failModes.includes('The generated hooks stay open even when the effective mode is `closed`'));
    assert.ok(failModes.includes('Copilot and Antigravity still run a call when the hook times out or cannot start'));
    assert.ok(failModes.includes('Under Secure Client they stay open'));
    for (const name of ['reference/connectors/copilot.mdx']) {
      const text = page(name);
      assert.ok(!/no fail-closed hook transport/i.test(text), name);
      assert.ok(text.includes('in fail mode `closed`, the default'), name);
    }
    for (const name of ['reference/connectors/antigravity.mdx']) {
      const text = page(name);
      assert.ok(!text.includes('A gateway failure lets the call run'), name);
      assert.ok(!text.includes('normal fail-open operation'), name);
      assert.ok(text.includes('In fail mode `closed`, the default'), name);
    }
  });

  it('keeps fail-open wording out of the connector summaries', () => {
    const matrix = JSON.parse(readFileSync(join(site, 'data/capability-matrix.json'), 'utf8')) as {
      connectors: { id: string; summary?: string }[];
    };
    for (const connector of matrix.connectors) {
      assert.ok(!/fail(ure)?-open/i.test(connector.summary ?? ''), `${connector.id} summary`);
    }
  });

  it('says an upgrade keeps only an open the config sets', () => {
    assert.ok(page('get-started/upgrade.mdx').includes("An upgrade sets each hook's fail mode from your config before the new hook runs"));
    assert.ok(page('reference/configuration/fail-modes.mdx').includes('`closed` outside Secure Client; `open` under it'));
    assert.ok(page('reference/configuration/fail-modes.mdx').includes('Hooks follow an open fail mode only when your config sets it'));
  });
});

describe('Hook connector setup and teardown', () => {
  it('limits the observe default to first setup in every CLI row and connector page', () => {
    const setupCode = source('cli/defenseclaw/commands/cmd_setup.py');
    const alias = setupCode.split('def _setup_observability_alias(')[1]?.split('def _')[0] ?? '';
    assert.match(alias, /mode = gc\.effective_mode\(connector\) if connector in _configured_connector_set\(gc\) else "observe"/);
    assert.match(alias, /if interactive and not mode_from_flag:\s+normalized_mode = _prompt_connector_mode\(connector, default_mode=normalized_mode\)/);
    const reference = readFileSync(join(site, 'content/docs/reference/commands/cli.mdx'), 'utf8');
    for (const { id, command } of hookConnectors) {
      const row = reference.split('\n').find((line) => line.startsWith(`| \`defenseclaw setup ${command}\` |`));
      assert.ok(row, `${id} CLI reference row is missing`);
      assert.match(row, /first setup.*observe|observe.*first setup/i, `${id} CLI row must qualify the default`);
      assert.match(row, /re-run.*keeps the current mode/i, `${id} CLI row must explain reruns`);

      const setup = page(`connectors/${id}.mdx`).split('## Set up')[1]?.split('## Check it')[0];
      assert.ok(setup, `${id} setup section is missing`);
      assert.match(setup, /first setup.*observe|observe.*first setup/i, `${id} page must qualify the default`);
      assert.match(setup, /re-run without `--mode` keeps the current mode/i, `${id} page must explain scripted reruns`);
    }
  });

  it('says what teardown removes and what it preserves on every connector page', () => {
    const guardrailCode = source('cli/defenseclaw/commands/cmd_guardrail.py');
    const sharedTeardown = source('internal/gateway/connector/hook_only.go');
    assert.match(guardrailCode, /def disable_cmd\([\s\S]*?if connector_flag:\s+_toggle_connector_guardrail\(/);
    assert.match(guardrailCode, /gc\.enabled = False[\s\S]*?if restart:[\s\S]*?_restart_services\(/);
    assert.match(sharedTeardown, /func \(c \*hookOnlyConnector\) Teardown\([\s\S]*?return c\.teardown\(ctx, opts, ""\)/);
    assert.match(sharedTeardown, /case !restored:[\s\S]*?c\.removeConfigEntriesWithManagedBackup\(/);
    assert.match(sharedTeardown, /if c\.pluginArtifact \{\s+return c\.teardownPluginArtifact\(opts\)/);
    for (const connector of ['cursor', 'devin', 'copilot', 'hermes', 'antigravity', 'opencode', 'amp']) {
      const factory = connector === 'devin' || connector === 'amp'
        ? source(`internal/gateway/connector/${connector}.go`)
        : sharedTeardown;
      assert.match(factory, new RegExp(`name:\\s*"${connector}"`), `${connector} must use the shared teardown`);
    }
    for (const connector of ['claudecode', 'codex', 'kiro']) {
      const implementation = source(`internal/gateway/connector/${connector}.go`);
      assert.match(implementation, /func \(c \*\w+Connector\) Teardown\(/, `${connector} must own its documented teardown`);
    }
    for (const { id, name } of hookConnectors) {
      const turnOff = page(`connectors/${id}.mdx`).split('## Turn it off')[1]?.split('## Details')[0];
      assert.ok(turnOff, `${id} turn-off section is missing`);
      assert.ok(!new RegExp(`This keeps ${name}'s settings`, 'i').test(turnOff), `${id} must not imply hooks stay installed`);
      if (id === 'opencode' || id === 'amp') {
        assert.match(turnOff, /removes? DefenseClaw's plugin/i, `${id} must name plugin removal`);
        assert.match(turnOff, /edited plugin.*(?:is left|is kept)/i, `${id} must explain edited plugins`);
        assert.match(turnOff, /guardrail enable.*(?:restores?|reinstalls?) DefenseClaw's plugin/i, `${id} must explain re-enable`);
      } else {
        assert.match(turnOff, /removes? DefenseClaw(?:'s)? hook/i, `${id} must name hook removal`);
        assert.match(turnOff, /guardrail enable.*(?:restores?|reinstalls?) DefenseClaw(?:'s)? hook/i, `${id} must explain re-enable`);
      }
      assert.match(turnOff, new RegExp(`preserves? (?:your|the) other ${name} settings`, 'i'), `${id} must preserve unrelated settings`);
    }
    const claude = page('connectors/claudecode.mdx').split('## Turn it off')[1]?.split('## Details')[0];
    assert.match(claude ?? '', /removes? DefenseClaw(?:'s)? hooks and OpenTelemetry settings/i);
    const kiro = page('connectors/kiro.mdx').split('## Turn it off')[1]?.split('## Details')[0];
    assert.match(kiro ?? '', /inert stub/i);
  });

  it('distinguishes whole-guardrail --no-restart from connector hot reload', () => {
    const guardrailCode = source('cli/defenseclaw/commands/cmd_guardrail.py');
    const gatewayCode = source('internal/gateway/sidecar.go');
    assert.match(guardrailCode, /def disable_cmd\([\s\S]*?if connector_flag:\s+_toggle_connector_guardrail\(/);
    assert.match(guardrailCode, /def _toggle_connector_guardrail\([\s\S]*?entry\.enabled = bool\(enable\)/);
    assert.match(guardrailCode, /gateway will continue running with the old policy[\s\S]*?until you restart it manually/);
    assert.match(gatewayCode, /guardrailRestart := connectorSetChanged\(oldCfg, newCfg\)/);
    assert.match(gatewayCode, /signalRestart\(s\.guardrailRestartCh\)/);
    const setup = page('connectors/claudecode.mdx').split('## Set up')[1]?.split('## Check it')[0];
    assert.match(setup ?? '', /re-run without `--mode` keeps the current mode/i);
    const turnOff = page('connectors/claudecode.mdx').split('## Turn it off')[1]?.split('## Details')[0];
    assert.match(turnOff ?? '', /whole-guardrail disable.*`--no-restart`.*restart the gateway/i);
    assert.match(turnOff ?? '', /`--connector claudecode`.*`--no-restart`.*running gateway.*(?:at once|without a restart)/i);
  });
});
