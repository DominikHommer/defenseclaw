import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

// Docs claims that must match what the product does. Each check reads the
// page as one line of words, so a reflowed paragraph still matches.

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

function assertCursorObserveOutageException(text: string, name: string): void {
  assert.match(
    text,
    /per-user Cursor in observe mode.{0,130}(?:fails open|allows the call).{0,130}`(?:guardrail\.)?hook_fail_mode`.{0,30}`closed`/i,
    `${name} must explain that Cursor observe ignores a closed fail-mode setting during an outage`,
  );
}

describe('per-user Cursor observe outage claims', () => {
  it('qualifies the coverage overview and failure table', () => {
    const coverage = page('appendix/coverage-by-layer.mdx');
    const overview = coverage.split('## Where each layer exists')[1]?.split('## Who sees and who enforces')[0] ?? '';
    const failureTable = coverage.split('## Fail-open and fail-closed, per layer')[1]?.split('## What Tetragon adds')[0] ?? '';
    assertCursorObserveOutageException(overview, 'coverage overview');
    const hookRow = /\| A hook cannot reach the gateway \|([^|]+)\|/.exec(failureTable)?.[1] ?? '';
    assertCursorObserveOutageException(hookRow, 'coverage hook outage row');
    assert.match(hookRow, /eligible managed outages/i);
  });

  it('qualifies the Cursor reference fail-mode contract', () => {
    const reference = page('reference/connectors/cursor.mdx');
    const failMode = reference.split('## Fail mode')[1]?.split('## Limits')[0] ?? '';
    assertCursorObserveOutageException(failMode, 'Cursor reference');
    assert.match(failMode, /managed.{0,120}(?:resolved|administrator).{0,80}fail mode/i);
    const managed = reference.split('### Enterprise standalone profile')[1]?.split('### OpenShell sandbox')[0] ?? '';
    assert.match(managed, /failClosed.{0,100}administrator.{0,50}resolved fail mode/i);
    assert.match(managed, /`true`.{0,50}`closed`.{0,100}`false`.{0,50}`open`/i);
  });

  it('qualifies installer outage guidance', () => {
    const startup = page('reference/commands/installer.mdx').split('## Startup behavior')[1]?.split('## Verify a download')[0] ?? '';
    assertCursorObserveOutageException(startup, 'installer guidance');
  });

  it('states the exception in the fail-mode reference', () => {
    const failModes = page('reference/configuration/fail-modes.mdx');
    assertCursorObserveOutageException(failModes.split('## Controls')[0] ?? '', 'fail-mode introduction');
    const controls = failModes.split('## Controls')[1]?.split('### Which value applies')[0] ?? '';
    assert.match(controls, /An explicit value selects the fail mode.{0,120}except for per-user Cursor/i);
    assertCursorObserveOutageException(
      failModes.split('### Which value applies')[1]?.split('### Refusals')[0] ?? '',
      'fail-mode precedence',
    );
    const secureClient = failModes.split('### Secure Client')[1]?.split('### Connectors without a fail-closed hook')[0] ?? '';
    assert.match(secureClient, /configured default.{0,60}`closed`.{0,100}per-user Cursor in observe mode.{0,60}`open`/i);
    const persisted = failModes.split('## Persisted fail mode')[1]?.split('## Connector response shapes')[0] ?? '';
    assert.match(persisted, /per-user Cursor.{0,90}observe mode.{0,90}installed.{0,70}`open`/i);
    assert.match(persisted, /Hooks follow an open fail mode only when your config sets it, except per-user Cursor in observe mode/i);
  });

  it('qualifies the guardrail feature summary', () => {
    const failMode = page('features/guardrail.mdx').split('## Fail mode')[1]?.split('## Which agents can ask')[0] ?? '';
    assertCursorObserveOutageException(failMode, 'guardrail summary');
    assert.match(failMode, /managed standalone host.{0,100}eligible gateway outages only/i);
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
    const setup = page('connectors/claudecode.mdx').split('## Set up')[1]?.split('## Check it')[0];
    assert.match(setup ?? '', /re-run without `--mode` keeps the current mode/i);
    const turnOff = page('connectors/claudecode.mdx').split('## Turn it off')[1]?.split('## Details')[0];
    assert.match(turnOff ?? '', /whole-guardrail disable.*`--no-restart`.*restart the gateway/i);
    assert.match(turnOff ?? '', /`--connector claudecode`.*`--no-restart`.*running gateway.*(?:at once|without a restart)/i);
  });
});
