import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { generateIngestScript } from '../src/lib/ingest-script.js';
import ingestRoutes from '../src/routes/ingest.js';

test('generateIngestScript produces valid shell script with injected base URL', () => {
  const script = generateIngestScript('http://localhost:3000');
  assert.ok(script.startsWith('#!/usr/bin/env bash') || script.startsWith('#!/bin/sh'));
  assert.ok(script.includes('BASE_URL="http://localhost:3000"'));
  assert.ok(script.includes('TARGET_SESSION_ID=""'));
  assert.ok(script.includes('${BASE_URL}/api/ingest/init'));
  assert.ok(script.includes('/finalize'));
  assert.ok(script.includes('curl'));
});

test('generateIngestScript embeds targetSessionId when provided', () => {
  const script = generateIngestScript('http://localhost:3000', 'test-session-123');
  assert.ok(script.includes('TARGET_SESSION_ID="test-session-123"'));
  assert.ok(script.includes('INIT_URL="${BASE_URL}/api/ingest/init"'));
  assert.ok(script.includes('Uploaded to active session! Switch to your browser to view merged metrics.'));
});

test('GET /ingest?session=xyz returns script with embedded session ID', async () => {
  const fastify = Fastify();
  await fastify.register(ingestRoutes);

  const res = await fastify.inject({
    method: 'GET',
    url: '/ingest?session=multi-node-xyz',
    headers: { 'user-agent': 'curl/8.0.1' },
  });

  assert.equal(res.statusCode, 200);
  assert.ok(res.body.includes('TARGET_SESSION_ID="multi-node-xyz"'));
});

