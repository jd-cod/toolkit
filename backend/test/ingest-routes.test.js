import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import ingestRoutes from '../src/routes/ingest.js';
import r2Storage from '../src/lib/r2-storage.js';

test('GET /ingest returns shell runner script for cURL user-agent', async () => {
  const fastify = Fastify();
  await fastify.register(ingestRoutes);

  const res = await fastify.inject({
    method: 'GET',
    url: '/ingest',
    headers: { 'user-agent': 'curl/7.88.1' },
  });

  assert.equal(res.statusCode, 200);
  assert.ok(res.headers['content-type'].includes('text/plain'));
  assert.ok(res.body.includes('#!/usr/bin/env bash'));
  assert.ok(res.body.includes('SysAdmin Toolkit Log Ingestion Runner'));
});

test('GET /ingest redirects web browser to /nginx', async () => {
  const fastify = Fastify();
  await fastify.register(ingestRoutes);

  const res = await fastify.inject({
    method: 'GET',
    url: '/ingest',
    headers: {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      accept: 'text/html,application/xhtml+xml',
    },
  });

  assert.equal(res.statusCode, 302);
  assert.ok(res.headers.location.endsWith('/nginx'));
});

test('POST /ingest/init creates presigned R2 upload session', async () => {
  if (!r2Storage.isEnabled()) {
    console.log('Skipping: R2 not configured');
    return;
  }
  const fastify = Fastify();
  await fastify.register(ingestRoutes);

  const res = await fastify.inject({
    method: 'POST',
    url: '/ingest/init',
  });

  assert.equal(res.statusCode, 200);
  const data = res.json();
  assert.equal(data.success, true);
  assert.ok(data.sessionId);
  assert.ok(data.uploadUrl);
  assert.ok(data.viewUrl.includes(`/nginx?session=${data.sessionId}`));
});

test('Full lifecycle: init -> PUT payload -> finalize -> get meta', async () => {
  if (!r2Storage.isEnabled()) {
    console.log('Skipping: R2 not configured');
    return;
  }
  const fastify = Fastify();
  await fastify.register(ingestRoutes);

  // 1. Init
  const initRes = await fastify.inject({ method: 'POST', url: '/ingest/init' });
  assert.equal(initRes.statusCode, 200);
  const { sessionId, uploadUrl } = initRes.json();

  // 2. PUT payload directly to R2 uploadUrl
  const testPayload = Buffer.from('test log line 1\ntest log line 2\n');
  const putRes = await fetch(uploadUrl, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/gzip' },
    body: testPayload,
  });
  assert.equal(putRes.status, 200);

  // 3. Finalize
  const finalizeRes = await fastify.inject({
    method: 'POST',
    url: `/ingest/${sessionId}/finalize`,
  });
  assert.equal(finalizeRes.statusCode, 200);
  const finalizeData = finalizeRes.json();
  assert.equal(finalizeData.success, true);
  assert.equal(finalizeData.compressedSize, testPayload.length);

  // 4. Meta check
  const metaRes = await fastify.inject({
    method: 'GET',
    url: `/ingest/${sessionId}/meta`,
  });
  assert.equal(metaRes.statusCode, 200);
  const metaData = metaRes.json();
  assert.equal(metaData.compressedSize, testPayload.length);

  // 5. Cleanup R2 object
  await r2Storage.deleteLog(`ephemeral/${sessionId}.log.gz`);
});
