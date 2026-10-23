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

function repoText(name: string): string {
  return readFileSync(join(repo, name), 'utf8').split(/\s+/).join(' ');
}

describe('1.0.4 managed outage and upgrade claims', () => {
  it('states the protected process-and-session record boundary everywhere operators see outage guidance', () => {
    const outagePages = [
      'reference/configuration/fail-modes.mdx',
      'enterprise/configure/reference.mdx',
      'enterprise/operate/reference.mdx',
      'enterprise/operate/lifecycle.mdx',
      'troubleshooting/enterprise/index.mdx',
    ];
    for (const name of outagePages) {
      const guidance = page(name);
      assert.match(guidance, /foreign_hooks: remove.*(?:process.*session|session.*process).*15 minutes/i, name);
      assert.doesNotMatch(guidance, /(?:guarded connectors|foreign-hook guard).*block outages too|outage blocks those calls too|Every call checked while the gateway is down is blocked/i, name);
    }
    const changelog = repoText('CHANGELOG.md');
    assert.doesNotMatch(changelog, /guarded connectors .*still block every tool call during a gateway outage/i);
    assert.doesNotMatch(changelog, /Every call checked while the gateway is down is blocked/i);
    assert.match(changelog, /During an outage under `open`, a guarded call runs only when the records of its agent process and its session/);
  });

  it('describes bounded Windows WAL catch-up and the remaining hook delay', () => {
    const enterprise = page('troubleshooting/enterprise/index.mdx');
    assert.match(enterprise, /Windows.*audit\.db-wal.*bounded catch-up/i);
    assert.match(enterprise, /bounded catch-up.*256 MiB/i);
    assert.match(enterprise, /0\.9.to.1\.2 GB.*10 calls a second/i);
    assert.match(enterprise, /hook answers.*(?:slow|wait|delay).*default.*closed/i);
    assert.doesNotMatch(enterprise, /audit\.db-wal.*20 GB|fix needs a change to how the audit store indexes hook records and is deferred/i);
  });

  it('keeps one supervisor upgrade entry with automatic stop and failed-stop recovery', () => {
    const changelog = repoText('CHANGELOG.md');
    assert.equal((changelog.match(/\*\*Sandboxes run only on OpenShell 0\.1\.5 or later\.\*\*/g) ?? []).length, 1);
    assert.match(changelog, /DefenseClaw stops it as soon as it sees it.*A stop that fails is a second finding/);
    assert.doesNotMatch(changelog, /A sandbox that keeps running through the upgrade keeps the old supervisor: the feed/);
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

describe('1.0.4 operator routes and limits', () => {
  it('keeps managed readers off per-user HITL commands', () => {
    const ask = page('how-to/guardrail/ask-before-risky-calls.mdx');
    assert.match(ask, /managed computer.*guardrail\.connectors\.<id>\.hilt/i);
    assert.match(ask, /per-user.*refus/i);
  });

  it('shows the managed OpenCode route', () => {
    const opencode = page('connectors/opencode.mdx');
    assert.match(opencode, /on a managed computer/i);
    assert.match(opencode, /guardrail\.connectors\.opencode/);
    assert.match(opencode, /enterprise policy verify/);
    assert.match(opencode, /\/etc\/opencode\/opencode\.json/);
  });

  it('points managed identity checks to the administrator command', () => {
    const identity = page('enterprise/identity/sources.mdx');
    const childDomain = identity.split('On a managed Linux host, check an account as root:')[1]?.split('### Windows')[0] ?? '';
    const groupRow = readFileSync(join(site, 'content/docs/enterprise/identity/sources.mdx'), 'utf8')
      .split('\n').find((line) => line.startsWith('| A group assignment never matches |')) ?? '';
    assert.match(identity, /administrator runs.*defenseclaw-gateway config validate/);
    assert.match(childDomain, /enterprise linux profile-explain --user/);
    assert.match(childDomain, /\/etc\/defenseclaw\/config\.yaml/);
    assert.match(childDomain, /per-user.*commands refuse/);
    assert.match(groupRow, /per-user install.*defenseclaw guardrail profile explain --user/);
    assert.match(groupRow, /managed Linux.*defenseclaw-gateway enterprise linux profile-explain --user/);
    assert.match(groupRow, /managed macOS.*defenseclaw-gateway enterprise macos profile-explain --user/);
    assert.match(groupRow, /managed Windows.*defenseclaw\.exe.*enterprise windows profile-explain --user/);
  });

  it('uses the managed Windows administrator route instead of a config-only shell', () => {
    const hooks = page('reference/commands/cli.mdx').split('### Per-user hooks (`enterprise hooks`)')[1]?.split('### ACP')[0] ?? '';
    const envVars = page('reference/configuration/env-vars.mdx');
    assert.match(hooks, /On managed Windows.*enterprise windows status.*enterprise windows verify/i);
    assert.match(hooks, /DEFENSECLAW_CONFIG.*alone.*does not.*guardian/i);
    assert.match(envVars, /On managed Windows.*elevated.*enterprise policy show --json.*without setting `DEFENSECLAW_CONFIG`/i);
    assert.doesNotMatch(envVars, /On Windows, set.*\$env:DEFENSECLAW_CONFIG/i);
  });

  it('keeps native-hook warnings and gives plugin readers a working report route', () => {
    const guard = page('enterprise/configure/foreign-hook-guard.mdx');
    assert.match(guard, /foreign_hooks: report.*enterprise policy show/i);
    assert.match(guard, /Cursor, Copilot and Devin.*defenseclaw-hook.*warning.*file and digest.*stderr/i);
    assert.match(guard, /Hermes.*stderr warning.*without the file and digest/i);
    assert.match(guard, /OpenCode and Amp.*enterprise policy show.*file and digest/i);
    assert.doesNotMatch(guard, /GAP-0697|(?:OpenCode|Amp).*drops.*warnings/i);
  });

  it('gives managed profile-explain routes in every identity troubleshooting row', () => {
    const rows = readFileSync(join(site, 'content/docs/enterprise/identity/sources.mdx'), 'utf8')
      .split('\n').filter((line) => line.startsWith('| ') && /profile explain/.test(line));
    assert.ok(rows.length >= 4, 'identity troubleshooting rows are missing');
    for (const row of rows) {
      assert.match(row, /managed.*enterprise .*profile-explain/i, row);
    }
  });

  it('gives a working managed restart route without promising it in the refusal', () => {
    const lifecycle = page('enterprise/operate/lifecycle.mdx');
    assert.match(lifecycle, /Windows \| Run the installed release's Setup with `\/repair JSON=1`/);
    assert.doesNotMatch(lifecycle, /the refusal names the commands below/i);
  });

  it('does not promise a Fleet error message that payload inspection cannot reach', () => {
    const fleet = page('reference/edge-connector/configuration.mdx');
    assert.match(fleet, /payload_invalid/);
    assert.match(fleet, /--payload <dir>/);
    assert.doesNotMatch(fleet, /`fleet\.enabled is set but the managed payload has no policy_compiler\.py`/);
  });

  it('matches the Windows Claude Code version floor', () => {
    const machine = page('enterprise/configure/machine-policy.mdx');
    assert.match(machine, /Windows.*2\.1\.219.*2\.1\.163.*2\.1\.218/);
    assert.doesNotMatch(machine, /floor stops no build/);
  });

  it('treats bare off as a YAML portability issue', () => {
    const machine = page('enterprise/configure/machine-policy.mdx');
    assert.doesNotMatch(machine, /bare `off`.*config refuses/);
    assert.match(machine, /Quote `"off"`.*YAML 1\.1/);
  });

  it('distinguishes config validation from OpenShell install checks', () => {
    for (const name of ['enterprise/runtime/sandboxes.mdx', 'enterprise/runtime/sandbox-reference.mdx']) {
      const sandboxes = page(name);
      assert.match(sandboxes, /config validate.*(?:schema|profile).*ensure.*(?:install|pin)/i, name);
      assert.match(sandboxes, /ensure.*install prerequisites.*exact OpenShell.*install: setup/i, name);
      assert.doesNotMatch(sandboxes, /exits 1 where the gateway would refuse/, name);
    }
  });

  it('gives an executable uninstall route after sandbox teardown', () => {
    const uninstall = page('get-started/uninstall.mdx');
    assert.match(uninstall, /If you already ran `defenseclaw sandbox teardown`.*add `--stop-sandboxes`/);
    assert.match(uninstall, /--stop-sandboxes.*running sandboxes/i);
  });

  it('only names Agent360 panels that ship', () => {
    const dashboard = readFileSync(
      join(repo, 'bundles/local_observability_stack/grafana/dashboards/defenseclaw-agent-360.json'),
      'utf8',
    );
    const agent360 = page('reference/observability/dashboards.mdx');
    assert.equal(agent360.includes('Last seen'), dashboard.includes('Last seen'));
  });

  it('omits the retired Omnigent bridge from current receipt paths', () => {
    const agent360 = page('reference/observability/dashboards.mdx');
    assert.doesNotMatch(agent360, /Omnigent policy bridge/i);
  });

  it('pins the workspace route for older Kiro IDEs', () => {
    const kiro = page('connectors/kiro.mdx');
    assert.match(kiro, /before 1\.0\.182.*setup kiro --workspace/i);
    assert.doesNotMatch(kiro, /Set `claw\.workspace_dir` to the project root before setup/);
  });

  it('states that CEL static cost can reject a regex below the size ceiling', () => {
    const engine = page('reference/policy/cel/engine.mdx');
    assert.match(engine, /512-byte CEL regex limit.*static cost limit can reject/i);
  });

  it('runs gateway examples on the pinned Go version through the shard runner', () => {
    for (const name of ['reference/policy/cel/engine.mdx', 'reference/policy/cel/authoring.mdx']) {
      const example = page(name);
      assert.match(example, /Go 1\.26\.4/, name);
      assert.match(example, /go test -timeout 30m \.\/internal\/guardrail\/semantic \.\/internal\/guardrail/, name);
      assert.match(example, /python3 scripts\/go_test_shards\.py --package-dir internal\/gateway --shard-count 16 -- go test -timeout 30m \.\/internal\/gateway/, name);
      assert.doesNotMatch(example, /go test -timeout 30m \.\/internal\/guardrail\/semantic \.\/internal\/guardrail \.\/internal\/gateway/, name);
    }
  });
});
