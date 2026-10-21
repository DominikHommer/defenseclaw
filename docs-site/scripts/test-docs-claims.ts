import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

// Docs claims that must match what the product does. Each check reads the
// page as one line of words, so a reflowed paragraph still matches. Claims
// that depend on what the Go code renders (fail modes) are checked by Go
// tests next to that code (internal/gateway/connector, internal/cli).

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');
const docs = join(site, 'content/docs');

function page(name: string): string {
  return readFileSync(join(docs, name), 'utf8').split(/\s+/).join(' ');
}

function pages(dir = docs): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return pages(path);
    return entry.name.endsWith('.mdx') ? [relative(docs, path).split(sep).join('/')] : [];
  });
}

function comparedKeys(file: string, pattern: RegExp, item: RegExp): string[] {
  const text = readFileSync(join(repo, file), 'utf8');
  const list = pattern.exec(text);
  assert.ok(list, `${file}: compared key list not found`);
  const keys = [...list[1].matchAll(item)].map((match) => match[1]);
  assert.ok(keys.length > 0, file);
  return keys;
}

describe('Intune base config versus the signed bundle', () => {
  const cases = [
    {
      name: 'enterprise/mdm/intune-windows.mdx',
      keys: comparedKeys(
        'packaging/mdm/intune/windows/New-DefenseClawIntunePackage.ps1',
        /foreach \(\$key in ((?:'[a-z_]+'(?:, )?)+)\)/,
        /'([a-z_]+)'/g,
      ),
    },
    ...['linux', 'macos'].map((os) => ({
      name: `enterprise/mdm/intune-${os}.mdx`,
      keys: comparedKeys(`packaging/mdm/${os}/defenseclaw-enterprise.sh`, /for key in ((?:[a-z_]+ ?)+); do/, /([a-z_]+)/g),
    })),
  ];
  for (const { name, keys } of cases) {
    it(`${name} names exactly the blocks its wrapper compares`, () => {
      const text = page(name);
      assert.ok(!text.includes('the packager checks this) so that window does not change what is blocked'), name);
      assert.ok(text.includes('No other setting is compared'), name);
      assert.ok(text.includes('such as `asset_policy:`, into the base config too'), name);
      for (const key of ['guardrail', ...keys]) {
        assert.ok(text.includes(`\`${key}:\``), `${name} does not name the compared ${key}: block`);
      }
    });
  }
});

describe('signed policy bundles stay off the general pages', () => {
  // Owner rule: no public signed-bundle page or guide until the sync service.
  // The Intune recipes keep the bundle delivery steps they had in 1.0.3.
  const intune = new Set(['linux', 'macos', 'windows'].map((os) => `enterprise/mdm/intune-${os}.mdx`));
  const bundleWords = /signed (policy )?bundle|policy bundle/i;

  it('has no bundle page or bundle heading outside the Intune recipes', () => {
    for (const name of pages()) {
      const raw = readFileSync(join(docs, name), 'utf8');
      const front = /^---\n([\s\S]*?)\n---/.exec(raw)?.[1] ?? '';
      for (const line of front.split('\n')) {
        if (/^(title|description):/.test(line)) assert.ok(!bundleWords.test(line), `${name}: ${line}`);
      }
      if (intune.has(name)) continue;
      for (const heading of raw.split('\n').filter((line) => /^#{1,6} /.test(line))) {
        assert.ok(!bundleWords.test(heading), `${name}: ${heading}`);
      }
    }
  });

  it('keeps the install-order guide and its links to the Intune Linux and macOS recipes', () => {
    const general = page('enterprise/mdm/index.mdx');
    assert.ok(!general.includes('install-order-with-a-signed-bundle'), 'enterprise/mdm/index.mdx links the bundle install order');
    assert.ok(!general.includes('A bundle-only run leaves the host unprotected'), 'enterprise/mdm/index.mdx carries the bundle install order');
    for (const name of pages()) {
      const text = readFileSync(join(docs, name), 'utf8');
      for (const match of text.matchAll(/\]\(([^)]*)#install-order-with-a-signed-bundle\)/g)) {
        const target = match[1] === '' ? name.replace(/\.mdx$/, '') : match[1].replace(/^\/docs\//, '');
        assert.ok(
          ['enterprise/mdm/intune-linux', 'enterprise/mdm/intune-macos'].includes(target),
          `${name} links the install order on ${target || 'itself'}`,
        );
      }
    }
  });
});

describe('managed Windows IDE inventory', () => {
  it('says redirected AppData is not read', () => {
    // The managed gateway service scans each profile's default AppData only
    // (internal/inventory detectEditorExtensions: platformIDEAppData runs for
    // the user's own gateway, never in a service context).
    const text = page('reference/ai-discovery.mdx');
    assert.ok(text.includes('so a profile whose AppData is redirected elsewhere is not read'));
    assert.ok(!/redirect\w* [^.]* is inventoried/i.test(text));
  });
});

describe('connector summaries', () => {
  it('keeps fail-open wording out of the connector summaries', () => {
    const matrix = JSON.parse(readFileSync(join(site, 'data/capability-matrix.json'), 'utf8')) as {
      connectors: { id: string; summary?: string }[];
    };
    for (const connector of matrix.connectors) {
      assert.ok(!/fail(ure)?-open/i.test(connector.summary ?? ''), `${connector.id} summary`);
    }
  });
});
