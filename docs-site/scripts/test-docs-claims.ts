import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
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

function docPages(dir = join(site, 'content/docs')): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? docPages(path) : entry.name.endsWith('.mdx') ? [path] : [];
  });
}

describe('managed ACP support', () => {
  it('keeps connector route notes consistent with managed enrollment', () => {
    for (const path of docPages()) {
      const text = readFileSync(path, 'utf8').split(/\s+/).join(' ');
      assert.doesNotMatch(text, /ACP editors are not supported in enterprise managed mode/i, path);
    }
    const kiro = page('reference/connectors/kiro.mdx');
    assert.ok(kiro.includes('/docs/features/acp-guard#managed-computers'));
    assert.match(kiro, /managed ACP.*preview/i);
    assert.match(page('get-started/support-matrix.mdx'), /enrollment.*preview/i);
  });
});

describe('managed outage documentation', () => {
  it('links every outage refusal to the capability matrix', () => {
    const text = readFileSync(join(site, 'content/docs/troubleshooting/enterprise/index.mdx'), 'utf8');
    for (const code of ['not_running', 'restarting', 'no_answer']) {
      const row = text.split('\n').find((line) => line.startsWith(`| \`enterprise_managed_gateway_${code}\` |`));
      assert.ok(row, code);
      assert.ok(row.includes('/docs/reference/apis/capability-matrix#gateway-outage'), code);
      assert.doesNotMatch(row, /it allows|allows this|never an allow|hook_fail_mode: open/, code);
    }
    assert.ok(page('appendix/coverage-by-layer.mdx').includes('/docs/reference/apis/capability-matrix#gateway-outage'));
  });
});

describe('installed fail mode environment contract', () => {
  it('does not classify the retired fail-mode input as tighten-only', () => {
    const text = page('troubleshooting/enterprise/hooks.mdx');
    const section = text.split('## A `DEFENSECLAW_*` variable or `.env` entry has no effect')[1]?.split('## ')[0];
    assert.ok(section, 'environment troubleshooting section');
    assert.match(section, /`DEFENSECLAW_FAIL_MODE` is not read by 1\.0\.4 hooks/);
    assert.match(section, /`DEFENSECLAW_STRICT_AVAILABILITY` and `DEFENSECLAW_HOOK_MAX_BODY`.*`tighten_only`/);
    assert.doesNotMatch(section, /`DEFENSECLAW_FAIL_MODE`, .*`tighten_only`/);
    assert.ok(section.includes('/docs/reference/apis/capability-matrix#gateway-outage'));
    const truth = page('reference/configuration/source-of-truth.mdx');
    assert.doesNotMatch(truth, /\| `tighten_only` \|[^|]*\|[^|]*DEFENSECLAW_FAIL_MODE/);
    const threat = page('enterprise/plan/threat-model.mdx');
    assert.doesNotMatch(threat, /`DEFENSECLAW_FAIL_MODE`, .*count only when stricter/);
  });
});

describe('quarantine publication and cleanup', () => {
  it('distinguishes an unpublished copy from failed source removal', () => {
    const text = page('reference/scanning/scanners.mdx');
    assert.doesNotMatch(text, /Two cases do not end in quarantine storage/);
    assert.match(text, /Before a verified copy is published.*files stay in place/i);
    assert.match(text, /After publication.*verified copy stays in quarantine storage/i);
    assert.match(text, /source.*partly or completely removed/i);
    assert.match(text, /`quarantine failed`.*install block and runtime disable stay/i);
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
    const matrix = JSON.parse(readFileSync(join(site, 'data/capability-matrix.json'), 'utf8'));
    for (const id of ['copilot', 'antigravity']) {
      const row = matrix.connectors.find((connector: { id: string }) => connector.id === id);
      assert.equal(row?.outage.perUserClosed, 'blocks', id);
      assert.equal(row?.hooks.blocksDeliveryFailures, true, id);
      const text = page(`reference/connectors/${id}.mdx`);
      assert.ok(text.includes('/docs/reference/apis/capability-matrix#gateway-outage'), id);
      assert.doesNotMatch(text, /no fail-closed hook transport|A gateway failure lets the call run|normal fail-open operation/i, id);
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
    assert.ok(page('reference/configuration/fail-modes.mdx').includes('Hooks follow an open fail mode only when your config sets it'));
  });
});
