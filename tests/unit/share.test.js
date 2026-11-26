import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_SHARE_EXPIRY,
  SHARE_EXPIRY_OPTIONS,
  SNAPSHOT_TOOLS,
  MAX_SHARE_PASSWORD_BYTES,
  describeShare,
  isSnapshotTool,
  shareLink,
  sharePasswordError,
} from '../../frontend/src/lib/share.ts';
import * as backend from '../../backend/src/lib/share-utils.js';

test('every expiry the dialog offers is one the backend accepts, and vice versa', () => {
  const offered = SHARE_EXPIRY_OPTIONS.map((option) => option.value);
  assert.deepEqual([...offered].sort(), [...backend.SHARE_EXPIRY_VALUES].sort());
  for (const value of offered) {
    assert.equal(backend.resolveExpiry(value).ok, true, `${value} must resolve`);
  }
  assert.ok(offered.includes(DEFAULT_SHARE_EXPIRY));
});

test('frontend and backend agree on which tools share snapshots', () => {
  assert.deepEqual([...SNAPSHOT_TOOLS].sort(), Object.keys(backend.SNAPSHOT_TOOLS).sort());
  assert.equal(isSnapshotTool('ssl'), true);
  assert.equal(isSnapshotTool('nginx'), false);
  assert.equal(isSnapshotTool(undefined), false);
});

test('password length limit matches the backend, counted in bytes after trimming', () => {
  assert.equal(MAX_SHARE_PASSWORD_BYTES, backend.MAX_SHARE_PASSWORD_BYTES);
  assert.equal(sharePasswordError(''), '');
  assert.equal(sharePasswordError(`  ${'a'.repeat(72)}  `), '');
  assert.notEqual(sharePasswordError('a'.repeat(73)), '');
  assert.notEqual(sharePasswordError('é'.repeat(37)), '', '37 two-byte characters exceed 72 bytes');
  assert.equal(backend.readSharePassword('é'.repeat(37)).ok, false);
});

test('share link and summary text', () => {
  assert.equal(shareLink('https://tools.example.com/', 'Ab12Cd34'), 'https://tools.example.com/s/Ab12Cd34');
  assert.equal(describeShare('7d', true), 'Expires in 7 days · Password protected');
  assert.equal(describeShare('never', false), 'Never expires · Anyone with the link can view');
});
