import assert from 'node:assert/strict';
import { test } from 'node:test';
import contracts from '../../cli/defenseclaw/inventory/hook_contracts.json' with { type: 'json' };
import { connectorById } from '../data/support-matrix';

test('Kiro support matrix gives the hook floors and uncovered upgrade state', () => {
  const kiro = connectorById('kiro');
  assert.ok(kiro);

  const { cli_hook_floor: cliFloor, ide_global_hooks_floor: ideFloor } = contracts.connectors.kiro;
  assert.equal(kiro.minVersion, `kiro-cli ${cliFloor}; Kiro IDE ${ideFloor}`);
  assert.match(kiro.versionNote ?? '', /managed status.*uncovered and verify fails/i);
  assert.match(kiro.versionNote ?? '', /earlier managed CLI enrollments keep their interactive hooks/i);
});
