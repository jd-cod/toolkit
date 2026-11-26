import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import ingestRoutes from '../src/routes/ingest.js';
import r2Storage from '../src/lib/r2-storage.js';

// Setup mock storage if R2 is not configured
const originalIsEnabled = r2Storage.isEnabled.bind(r2Storage);
const originalHead = r2Storage.headObject?.bind(r2Storage);
const originalDelete = r2Storage.deleteLog?.bind(r2Storage);
const originalUploadUrl = r2Storage.generatePresignedUploadUrl?.bind(r2Storage);
const originalDownloadUrl = r2Storage.generatePresignedDownloadUrl?.bind(r2Storage);

const storageStore = new Map();

function setupMockStorage() {
  r2Storage.isEnabled = () => true;
  r2Storage.generatePresignedUploadUrl = async (key) => `https://mock-r2.test/${key}?signed=upload`;
  r2Storage.generatePresignedDownloadUrl = async (key) => `https://mock-r2.test/${key}?signed=download`;
  r2Storage.headObject = async (key) => {
    const obj = storageStore.get(key) || { size: 1024, metadata: {} };
    return obj;
  };
  r2Storage.deleteLog = async (key) => {
    storageStore.delete(key);
  };
}

function restoreMockStorage() {
  r2Storage.isEnabled = originalIsEnabled;
  if (originalHead) r2Storage.headObject = originalHead;
  if (originalDelete) r2Storage.deleteLog = originalDelete;
  if (originalUploadUrl) r2Storage.generatePresignedUploadUrl = originalUploadUrl;
  if (originalDownloadUrl) r2Storage.generatePresignedDownloadUrl = originalDownloadUrl;
}

test('Multi-Node Ingest Lifecycle and Queue API', async (t) => {
  setupMockStorage();
  t.after(restoreMockStorage);

  const fastify = Fastify();
  await fastify.register(ingestRoutes);

  // 1. POST /ingest/init creates fresh session with chunk-1
  const initRes1 = await fastify.inject({
    method: 'POST',
    url: '/ingest/init',
  });
  assert.equal(initRes1.statusCode, 200);
  const data1 = initRes1.json();
  assert.equal(data1.success, true);
  assert.ok(data1.sessionId);
  assert.equal(data1.chunkId, 'chunk-1');
  assert.equal(data1.isAppend, false);
  const sessionId = data1.sessionId;

  // 2. Finalize chunk-1
  storageStore.set(`ephemeral/${sessionId}/chunk-1.log.gz`, { size: 2048, metadata: {} });
  const finRes1 = await fastify.inject({
    method: 'POST',
    url: `/ingest/${sessionId}/finalize?chunkId=chunk-1`,
    headers: { 'user-agent': 'curl/7.88.1' }
  });
  assert.equal(finRes1.statusCode, 200);
  assert.ok(finRes1.body.includes('Nginx Log Analysis Ready!'));

  // 3. POST /ingest/init with existing sessionId returns chunk-2 with isAppend: true
  const initRes2 = await fastify.inject({
    method: 'POST',
    url: `/ingest/init?sessionId=${sessionId}`,
  });
  assert.equal(initRes2.statusCode, 200);
  const data2 = initRes2.json();
  assert.equal(data2.success, true);
  assert.equal(data2.sessionId, sessionId);
  assert.equal(data2.chunkId, 'chunk-2');
  assert.equal(data2.isAppend, true);

  // 4. Finalize chunk-2 from cURL user-agent should return multi-node friendly message
  storageStore.set(`ephemeral/${sessionId}/chunk-2.log.gz`, { size: 4096, metadata: {} });
  const finRes2 = await fastify.inject({
    method: 'POST',
    url: `/ingest/${sessionId}/finalize?chunkId=chunk-2`,
    headers: { 'user-agent': 'curl/7.88.1' }
  });
  assert.equal(finRes2.statusCode, 200);
  assert.ok(finRes2.body.includes('Uploaded to active session! Switch to your browser to view merged metrics.'));
  assert.ok(finRes2.body.includes(`/nginx?session=${sessionId}`));

  // 5. POST /ingest/init with existing sessionId returns chunk-3
  const initRes3 = await fastify.inject({
    method: 'POST',
    url: `/ingest/init?sessionId=${sessionId}`,
  });
  assert.equal(initRes3.statusCode, 200);
  const data3 = initRes3.json();
  assert.equal(data3.chunkId, 'chunk-3');

  storageStore.set(`ephemeral/${sessionId}/chunk-3.log.gz`, { size: 8192, metadata: {} });
  await fastify.inject({
    method: 'POST',
    url: `/ingest/${sessionId}/finalize?chunkId=chunk-3`,
  });

  // 6. GET /ingest/:sessionId/queue returns pending chunks in FIFO order
  const queueRes = await fastify.inject({
    method: 'GET',
    url: `/ingest/${sessionId}/queue`,
  });
  assert.equal(queueRes.statusCode, 200);
  const queueData = queueRes.json();
  assert.equal(queueData.success, true);
  assert.ok(Array.isArray(queueData.chunks));
  // chunk-2 and chunk-3 should be in queue in FIFO order
  assert.equal(queueData.chunks.length, 2);
  assert.equal(queueData.chunks[0].chunkId, 'chunk-2');
  assert.equal(queueData.chunks[1].chunkId, 'chunk-3');

  // 7. GET /ingest/:sessionId/chunk/:chunkId returns presigned download URL
  const chunkDlRes = await fastify.inject({
    method: 'GET',
    url: `/ingest/${sessionId}/chunk/chunk-2`,
  });
  assert.equal(chunkDlRes.statusCode, 200);
  const chunkDlData = chunkDlRes.json();
  assert.equal(chunkDlData.success, true);
  assert.ok(chunkDlData.downloadUrl.includes('chunk-2.log.gz'));

  // 8. POST /ingest/:sessionId/chunk/:chunkId/purge purges chunk from storage and marks consumed
  const purgeRes = await fastify.inject({
    method: 'POST',
    url: `/ingest/${sessionId}/chunk/chunk-2/purge`,
  });
  assert.equal(purgeRes.statusCode, 200);
  assert.equal(storageStore.has(`ephemeral/${sessionId}/chunk-2.log.gz`), false);

  // Queue should now only have chunk-3
  const queueResAfterPurge = await fastify.inject({
    method: 'GET',
    url: `/ingest/${sessionId}/queue`,
  });
  const queueDataAfterPurge = queueResAfterPurge.json();
  assert.equal(queueDataAfterPurge.chunks.length, 1);
  assert.equal(queueDataAfterPurge.chunks[0].chunkId, 'chunk-3');

  // 9. POST /ingest/:sessionId/chunk/:chunkId/discard discards chunk from storage and queue
  const discardRes = await fastify.inject({
    method: 'POST',
    url: `/ingest/${sessionId}/chunk/chunk-3/discard`,
  });
  assert.equal(discardRes.statusCode, 200);
  assert.equal(storageStore.has(`ephemeral/${sessionId}/chunk-3.log.gz`), false);

  const queueResAfterDiscard = await fastify.inject({
    method: 'GET',
    url: `/ingest/${sessionId}/queue`,
  });
  assert.equal(queueResAfterDiscard.json().chunks.length, 0);

  // 10. POST /ingest/:sessionId/heartbeat extends TTL
  const hbRes = await fastify.inject({
    method: 'POST',
    url: `/ingest/${sessionId}/heartbeat`,
  });
  assert.equal(hbRes.statusCode, 200);
  assert.equal(hbRes.json().success, true);
  assert.ok(new Date(hbRes.json().expiresAt).getTime() > Date.now());

  // 11. POST /ingest/:sessionId/destroy purges session
  const destroyRes = await fastify.inject({
    method: 'POST',
    url: `/ingest/${sessionId}/destroy`,
  });
  assert.equal(destroyRes.statusCode, 200);
  assert.equal(destroyRes.json().success, true);

  // Checking queue now returns 404
  const queueResAfterDestroy = await fastify.inject({
    method: 'GET',
    url: `/ingest/${sessionId}/queue`,
  });
  assert.equal(queueResAfterDestroy.statusCode, 404);
});
