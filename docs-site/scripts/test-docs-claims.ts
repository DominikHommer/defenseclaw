import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

// Docs claims that must match what the product does. Each check reads the
// page as one line of words, so a reflowed paragraph still matches.

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');

function page(name: string): string {
  return readFileSync(join(site, 'content/docs', name), 'utf8').split(/\s+/).join(' ');
}

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

function source(name: string): string {
  return readFileSync(join(repo, name), 'utf8');
}

describe('agent identity rows (rel-1-0-4 GAP-0596)', () => {
  it('documents every JSON field the row has, on every OS', () => {
    const record = source('internal/inventory/agent_identity_store.go');
    const api = page('reference/apis/gateway-api.mdx');
    for (const field of ['upn', 'subagents_seen', 'last_subagent_id']) {
      assert.ok(new RegExp('json:"' + field + '[,"]').test(record), `AgentIdentityRecord has no ${field} JSON field`);
      assert.ok(api.includes(`"${field}":`), `the agents/identities example shows no ${field}`);
      assert.ok(api.includes(`\`${field}\``), `the agents/identities text does not explain ${field}`);
    }
    assert.ok(api.includes('Linux, macOS and Windows rows carry the same fields'));
  });

  it('explains when a cold Windows AD UPN reaches an existing row', () => {
    const identity = source('internal/gateway/agent_identity.go');
    const recorder = source('internal/gateway/agent_identity_recorder.go');
    const store = source('internal/inventory/agent_identity_store.go');
    const windows = source('internal/gateway/identity_resolve_windows.go');
    const cache = source('internal/gateway/identity_directory_cache.go');
    const ad = source('internal/useridentity/directory_windows_facts.go');
    const spool = source('internal/enterprisehooks/identity_spool_windows.go');
    assert.match(identity, /func agentIdentityAccountUPN\(userID string\) \(upn string, known bool\)[\s\S]*?peerDirectoryCache\(\)\.peekCurrent\(userID\)/);
    assert.ok(identity.includes('readIdentitySpoolFacts(userID, time.Now())'));
    assert.ok(cache.includes('!entry.failedSince.IsZero()'));
    assert.ok(cache.includes('entry.fetchedAt.Add(c.lifetime(entry.facts))'));
    assert.ok(ad.includes('entry.kept = entry.upn != ""'));
    assert.ok(spool.includes('KeepLastKnownUPN(record, entry.previous)'));
    assert.ok(identity.includes('record.UPNSource == enterprisehooks.UPNSourceWindowsKept'));
    assert.ok(identity.includes('if facts.UPNKept {'));
    assert.match(windows, /wait := time\.Duration\(0\)[\s\S]*?if identityLookupBlocking\.Load\(\)/);
    assert.ok(recorder.includes('rec.UPN = facts.UserUPN'));
    assert.ok(recorder.includes('rec.UPN = buffered.UPN'));
    assert.ok(store.includes('user_upn = excluded.user_upn'));

    const api = page('reference/apis/gateway-api.mdx');
    const upn = api.slice(api.indexOf('`upn` is the account'), api.indexOf('`total` counts'));
    assert.ok(upn.includes('current Windows guardian record takes precedence'));
    assert.ok(upn.includes('an expired or failed directory answer omits'));
    assert.ok(upn.includes('last verified Windows AD UPN can remain available for profile matching'));
    assert.ok(upn.includes('an earlier value is'));
    assert.ok(upn.includes('A completed background lookup does not update the row by itself; another hook must run'));

    const reference = page('enterprise/identity/reference.mdx');
    assert.ok(reference.includes('another hook runs after the directory cache has a current UPN'));
    assert.ok(reference.includes('last verified AD UPN is kept for profile matching'));
    assert.ok(reference.includes("Each hook replaces the row's UPN"));
  });
});

describe('Windows AD UPN outage wording', () => {
  it('keeps policy continuity separate from current identity rows', () => {
    const sources = page('enterprise/identity/sources.mdx');
    const row = sources.split('| AD UPN |')[1]?.split('| Verified |')[0];
    assert.ok(row, 'the Windows AD UPN source row is missing');
    assert.ok(row.includes('last verified UPN is kept for profile matching'), 'the outage policy behavior is missing');
    assert.ok(row.includes('omitted from agent identity rows'), 'the current row behavior is missing');
    assert.ok(source('internal/enterprisehooks/identity_spool.go').includes('UPNSourceWindowsKept = "windows_kept"'));
    assert.ok(source('internal/useridentity/directory_windows_facts.go').includes('upn, kept = previous, previous != ""'));
    const changelog = source('CHANGELOG.md');
    assert.ok(changelog.includes('last verified UPN for profile matching'));
    assert.ok(changelog.includes('omit that kept UPN'));
  });
});

describe('the TUI page on a managed computer (rel-1-0-4 GAP-0597)', () => {
  it('quotes the launcher refusal and links the managed-device steps', () => {
    const refusal = /launcherRefusal = "([^"]+)"/.exec(source('internal/cli/launcher.go'));
    assert.ok(refusal, 'launcher refusal not found');
    const tui = page('features/tui.mdx');
    assert.ok(tui.includes(refusal[1]), 'features/tui.mdx does not quote the launcher refusal');
    assert.ok(tui.includes('/docs/reference/commands/tui#on-a-managed-device'));
    assert.ok(page('reference/commands/tui.mdx').includes('#### On a managed device'));
  });
});

describe('Windows event log check (rel-1-0-4 GAP-0598)', () => {
  it('names enterprise windows events and each of its flags', () => {
    const command = source('internal/cli/windows_enterprise_event_check.go');
    assert.ok(command.includes('Use:   "events"'));
    const flags = [...command.matchAll(/Flags\(\)\.\w+Var\(&\w+, "([a-z-]+)"/g)].map((match) => match[1]);
    assert.deepEqual(flags.sort(), ['application', 'json', 'max']);
    const operations = page('enterprise/operate/operations.mdx');
    assert.ok(operations.includes('enterprise windows events'), 'operations.mdx does not name enterprise windows events');
    for (const flag of flags) {
      assert.ok(operations.includes(`--${flag}`), `operations.mdx does not explain --${flag}`);
    }
    assert.ok(command.includes('within two minutes') && operations.includes('within two minutes'));
    assert.ok(page('reference/commands/cli.mdx').includes('| `events` | Standalone |'));
  });
});

describe('Hermes tool-call state (rel-1-0-4 GAP-0599)', () => {
  it('keeps committed steps across the per-turn on_session_end, as the contract does', () => {
    const contracts = JSON.parse(source('cli/defenseclaw/inventory/hook_contracts.json')) as {
      connectors: Record<string, { contracts: { contract_id: string; tool_call_lifecycle: Record<string, unknown> }[] }>;
    };
    for (const contract of contracts.connectors.hermes.contracts) {
      const lifecycle = contract.tool_call_lifecycle;
      assert.equal(lifecycle.stateful_enforcement_level, 'paired-outcomes', contract.contract_id);
      assert.deepEqual(lifecycle.authoritative_pending_discard_events, ['on_session_end'], contract.contract_id);
      assert.ok(!(lifecycle.authoritative_terminal_events as string[]).includes('on_session_end'), contract.contract_id);
    }
    const state = page('reference/policy/cel/tool-call-state.mdx');
    assert.ok(state.includes('Hermes `on_session_end` (which Hermes sends at the end of every turn'));
    assert.ok(/\| \[Hermes\][^\n]*\| `paired-outcomes` \|/.test(readFileSync(join(site, 'content/docs/reference/policy/cel/tool-call-state.mdx'), 'utf8')));
  });
});
