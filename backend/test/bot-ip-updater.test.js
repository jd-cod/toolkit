import test from 'node:test';
import assert from 'node:assert/strict';
import { sourceSyncCounts } from '../src/lib/bot-ip-updater.js';

test.describe('Bot IP source startup sync', () => {
  test('a database where no source was ever synced is recognised as such', () => {
    // mysql2 returns COUNT(*) as a number and SUM() as a string.
    const counts = sourceSyncCounts({ total: 16, synced: '0' });
    assert.deepEqual(counts, { total: 16, synced: 0 });
    assert.equal(counts.total > 0 && counts.synced === 0, true);
  });

  test('synced sources are counted', () => {
    assert.deepEqual(sourceSyncCounts({ total: 16, synced: '12' }), { total: 16, synced: 12 });
  });

  test('an empty table gives zeros', () => {
    assert.deepEqual(sourceSyncCounts({ total: 0, synced: null }), { total: 0, synced: 0 });
    assert.deepEqual(sourceSyncCounts(undefined), { total: 0, synced: 0 });
  });
});
