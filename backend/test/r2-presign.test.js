import test from 'node:test';
import assert from 'node:assert/strict';
import r2Storage from '../src/lib/r2-storage.js';

test('r2Storage exposes generatePresignedUploadUrl when enabled', async () => {
  if (!r2Storage.isEnabled()) {
    console.log('Skipping: R2 not configured in this test env');
    return;
  }
  const url = await r2Storage.generatePresignedUploadUrl('ephemeral/test-unit.log.gz', 300);
  assert.ok(typeof url === 'string');
  assert.ok(url.includes('X-Amz-Signature') || url.includes('Signature'));
  assert.ok(url.includes('ephemeral/test-unit.log.gz'));
});

test('r2Storage exposes headObject when enabled', async () => {
  if (!r2Storage.isEnabled()) {
    console.log('Skipping: R2 not configured in this test env');
    return;
  }
  const result = await r2Storage.headObject('ephemeral/non-existent-test-file.log.gz');
  assert.equal(result, null);
});
