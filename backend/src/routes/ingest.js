/**
 * Ephemeral Ingestion Routes — Fastify + R2 Storage
 *
 * Allows sysadmins to pipe logs straight from terminal/SSH into the web UI:
 *   tail -n 50000 /var/log/nginx/access.log | curl -F "file=@-" https://domain.com/api/ingest
 *   cat access.log | curl -X POST --data-binary @- https://domain.com/api/ingest
 *
 * Privacy & Performance Optimization:
 *  - 100% Ephemeral: R2 object storage with strict 10-minute TTL.
 *  - High Performance: Stores & streams compressed GZIP payloads directly to reduce bandwidth by 90%+.
 *  - Zero Data Retention: Automatically purged immediately upon first retrieval.
 *  - Client-Side Decompression: Modern browser Web Streams / DecompressionStream unpacks in memory.
 */

import crypto from 'crypto';
import zlib from 'zlib';
import { promisify } from 'util';
import r2Storage from '../lib/r2-storage.js';
import { generateIngestScript, isSafeBaseUrl, sanitizeSessionId } from '../lib/ingest-script.js';

const gzipAsync = promisify(zlib.gzip);
const MAX_COMPRESSED_BYTES = 250 * 1024 * 1024; // 250 MB max compressed upload (~2-2.5 GB uncompressed logs)
const MAX_RAW_INGEST_BYTES = 500 * 1024 * 1024; // 500 MB max if uploading uncompressed text
const MAX_DECOMPRESSED_BYTES = 2048 * 1024 * 1024; // 2 GB safety ceiling for browser heap
const MAX_BODY_LIMIT = 500 * 1024 * 1024; // 500 MB multipart/body limit
const SESSION_TTL_MS = 15 * 60 * 1000; // 15 minutes TTL for multi-node sessions
const MULTI_NODE_TTL_MS = 15 * 60 * 1000;

// In-memory ephemeral session metadata map: sessionId -> { sessionId, r2Key, chunks, nextChunkIndex, createdAt, expiresAt }
const ephemeralSessions = new Map();

// Sessions whose presigned download URL has already been issued, with the time of issue.
// The R2 object cannot be deleted at redirect time — the browser has not fetched it yet —
// so the client calls POST /ingest/:id/purge once the download completes, which honours
// delete-on-first-view without breaking the in-flight transfer.
// Entries are kept for a grace window well beyond any plausible download, and are only
// then swept — the client may legitimately take minutes to read a large log.
const consumedSessions = new Map(); // sessionId -> issuedAt
const CONSUMED_GRACE_MS = 30 * 60 * 1000; // 30 minutes

// Periodic cleanup of expired sessions every 60 seconds
setInterval(async () => {
  const now = Date.now();
  for (const [id, session] of ephemeralSessions.entries()) {
    if (now > session.expiresAt) {
      ephemeralSessions.delete(id);
      // Delete from R2
      if (session.r2Key && r2Storage.isEnabled()) {
        r2Storage.deleteLog(session.r2Key).catch(() => {});
      }
    }
  }
  // Safety net: delete objects for consumed sessions the client never purged
  // (closed tab, network failure). Also prunes the bookkeeping.
  for (const [id, issuedAt] of consumedSessions) {
    if (now - issuedAt > CONSUMED_GRACE_MS) {
      consumedSessions.delete(id);
      if (r2Storage.isEnabled()) {
        r2Storage.deleteLog(`ephemeral/${id}.log.gz`).catch(() => {});
      }
    }
  }
}, 60 * 1000).unref();

const SAFE_HOST = /^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$/;
const CHUNK_ID = /^chunk-\d{1,6}$/;

function firstHeaderValue(value) {
  const raw = Array.isArray(value) ? value[0] : value;
  return typeof raw === 'string' ? raw.split(',')[0].trim() : '';
}

// The result is embedded in the bash runner script and in links shown to the
// user, and Host / X-Forwarded-* are client-controlled, so only a plain
// scheme and host[:port] are accepted. Set APP_URL to pin it.
function getPublicBaseUrl(request) {
  if (process.env.APP_URL) {
    const configured = process.env.APP_URL.replace(/\/+$/, '');
    if (isSafeBaseUrl(configured)) return configured;
  }
  const proto = firstHeaderValue(request.headers['x-forwarded-proto']).toLowerCase() === 'https' ? 'https' : 'http';
  const rawHost = firstHeaderValue(request.headers['x-forwarded-host']) || firstHeaderValue(request.headers.host);
  const host = SAFE_HOST.test(rawHost) ? rawHost : 'localhost:3000';
  const frontendHost = host.replace(/:4000$/, ':3000');
  return `${proto}://${frontendHost}`;
}

export default async function ingestRoutes(fastify, opts) {
  // Register fastify-multipart plugin if not already registered
  if (!fastify.hasContentTypeParser('multipart/form-data')) {
    try {
      const multipart = (await import('@fastify/multipart')).default;
      await fastify.register(multipart, {
        limits: {
          fileSize: MAX_BODY_LIMIT,
          files: 1,
        },
      });
    } catch (err) {
      fastify.log.warn(`Multipart plugin registration note: ${err.message}`);
    }
  }

  // Register content type parsers for stream, gzip, octet-stream, text, etc.
  const supportedTypes = [
    'text/plain',
    'text/x-log',
    'application/octet-stream',
    'application/gzip',
    'application/x-gzip',
    'application/binary',
    'application/x-www-form-urlencoded',
  ];

  for (const contentType of supportedTypes) {
    if (!fastify.hasContentTypeParser(contentType)) {
      fastify.addContentTypeParser(
        contentType,
        { parseAs: 'buffer', bodyLimit: MAX_BODY_LIMIT },
        (req, body, done) => {
          done(null, body);
        }
      );
    }
  }

  // GET /ingest (or /api/ingest) — Shell runner script for CLI or browser redirect
  fastify.get('/ingest', async (request, reply) => {
    const accept = (request.headers['accept'] || '').toLowerCase();
    const userAgent = (request.headers['user-agent'] || '').toLowerCase();

    // If accessed from a web browser, redirect to the Nginx Analyzer dashboard
    if (accept.includes('text/html') && !userAgent.includes('curl') && !userAgent.includes('wget') && !userAgent.includes('httpie')) {
      const baseUrl = getPublicBaseUrl(request);
      return reply.code(302).redirect(`${baseUrl}/nginx`);
    }

    const baseUrl = getPublicBaseUrl(request);
    const targetSession = sanitizeSessionId(request.query?.session);
    reply.type('text/plain; charset=utf-8');
    return generateIngestScript(baseUrl, targetSession);
  });

  // POST /ingest/init (or /api/ingest/init) — Obtain presigned R2 upload URL for large uploads
  fastify.post('/ingest/init', async (request, reply) => {
    if (!r2Storage.isEnabled()) {
      return reply.code(503).send({ error: 'Storage service is not configured.' });
    }

    const reqSessionId = request.query?.sessionId || request.body?.sessionId || null;
    let sessionId = reqSessionId;
    let isAppend = false;
    let session = sessionId ? ephemeralSessions.get(sessionId) : null;
    let chunkId = 'chunk-1';
    const now = Date.now();

    if (session && now <= session.expiresAt) {
      isAppend = true;
      session.nextChunkIndex = (session.nextChunkIndex || 1) + 1;
      chunkId = `chunk-${session.nextChunkIndex}`;
      session.expiresAt = now + MULTI_NODE_TTL_MS;
    } else {
      sessionId = crypto.randomBytes(12).toString('hex');
      session = {
        sessionId,
        createdAt: now,
        expiresAt: now + MULTI_NODE_TTL_MS,
        chunks: new Map(),
        nextChunkIndex: 1,
        compressedSize: 0,
        decompressedSize: 0,
        lineCount: 0,
        finalized: false,
      };
      ephemeralSessions.set(sessionId, session);
    }

    const r2Key = `ephemeral/${sessionId}/${chunkId}.log.gz`;
    if (chunkId === 'chunk-1') {
      session.r2Key = r2Key;
    }

    try {
      const uploadUrl = await r2Storage.generatePresignedUploadUrl(r2Key, 900);
      const baseUrl = getPublicBaseUrl(request);
      const viewUrl = `${baseUrl}/nginx?session=${sessionId}`;

      return {
        success: true,
        sessionId,
        chunkId,
        uploadUrl,
        viewUrl,
        isAppend,
        expiresAt: new Date(session.expiresAt).toISOString(),
      };
    } catch (err) {
      fastify.log.error('Failed to generate presigned upload URL:', err);
      return reply.code(500).send({ error: 'Failed to initialize upload session.' });
    }
  });

  // POST /ingest/:sessionId/finalize (or /api/ingest/:sessionId/finalize) — Verify uploaded object
  fastify.post('/ingest/:sessionId/finalize', async (request, reply) => {
    const { sessionId } = request.params;
    const session = ephemeralSessions.get(sessionId);

    if (!session || Date.now() > session.expiresAt) {
      return reply.code(404).send({ error: 'Session not found or expired.' });
    }

    const reqChunkId = request.query?.chunkId || request.body?.chunkId || (session.nextChunkIndex > 1 ? `chunk-${session.nextChunkIndex}` : 'chunk-1');
    // The chunk ID becomes part of a storage key; only IDs issued by /ingest/init are valid.
    if (typeof reqChunkId !== 'string' || !CHUNK_ID.test(reqChunkId)) {
      return reply.code(400).send({ error: 'Invalid chunk ID.' });
    }
    const r2Key = `ephemeral/${sessionId}/${reqChunkId}.log.gz`;

    try {
      let head = await r2Storage.headObject(r2Key);
      let headKey = r2Key;
      if ((!head || head.size === 0) && reqChunkId === 'chunk-1' && session.r2Key && session.r2Key !== r2Key) {
        head = await r2Storage.headObject(session.r2Key);
        headKey = session.r2Key;
      }
      if (!head || head.size === 0) {
        return reply.code(400).send({ error: 'No uploaded data detected in storage.' });
      }
      // A presigned upload URL cannot cap the object size, so enforce the same
      // ceiling as the direct upload path here and drop anything larger.
      if (head.size > MAX_COMPRESSED_BYTES) {
        await r2Storage.deleteLog(headKey).catch(() => {});
        return reply.code(413).send({
          error: `Compressed log size (${Math.round(head.size / (1024 * 1024))} MB) exceeds the ${Math.round(MAX_COMPRESSED_BYTES / (1024 * 1024))} MB limit.`,
        });
      }

      const chunkData = {
        chunkId: reqChunkId,
        r2Key,
        compressedSize: head.size,
        decompressedSize: head.metadata?.['decompressed-size'] ? parseInt(head.metadata['decompressed-size'], 10) : head.size,
        lineCount: head.metadata?.['line-count'] ? parseInt(head.metadata['line-count'], 10) : 0,
        status: 'pending',
        uploadedAt: Date.now(),
      };

      if (!session.chunks) session.chunks = new Map();
      session.chunks.set(reqChunkId, chunkData);
      session.compressedSize = head.size;
      session.finalized = true;
      session.expiresAt = Date.now() + MULTI_NODE_TTL_MS;

      const baseUrl = getPublicBaseUrl(request);
      const viewUrl = `${baseUrl}/nginx?session=${sessionId}`;
      const userAgent = (request.headers['user-agent'] || '').toLowerCase();
      const acceptHeader = (request.headers['accept'] || '').toLowerCase();

      if (!acceptHeader.includes('application/json') && (userAgent.includes('curl') || userAgent.includes('wget') || userAgent.includes('httpie') || acceptHeader === 'text/plain')) {
        reply.type('text/plain');
        if (reqChunkId !== 'chunk-1') {
          return `\n✅ Uploaded to active session! Switch to your browser to view merged metrics.\n\n👉 Dashboard: ${viewUrl}\n\n`;
        }
        return `\n🚀 Nginx Log Analysis Ready!\n\n👉 View Dashboard: ${viewUrl}\n\nℹ️  Note: This link is valid for 15 minutes and is automatically deleted upon first viewing.\n\n`;
      }

      return {
        success: true,
        sessionId,
        chunkId: reqChunkId,
        url: viewUrl,
        compressedSize: head.size,
      };
    } catch (err) {
      fastify.log.error(`Error finalizing session ${sessionId}:`, err);
      return reply.code(500).send({ error: 'Failed to finalize upload session.' });
    }
  });

  // POST /api/ingest — Accept log upload via cURL / stream (stores compressed in R2)
  fastify.post('/ingest', { bodyLimit: MAX_BODY_LIMIT }, async (request, reply) => {
    if (!r2Storage.isEnabled()) {
      return reply.code(503).send({ error: 'Storage service is not configured.' });
    }

    let inputBuffer = null;

    // Check if multipart form upload (curl -F "file=@...")
    if (request.isMultipart && request.isMultipart()) {
      const part = await request.file();
      if (part) {
        inputBuffer = await part.toBuffer();
      }
    } else if (Buffer.isBuffer(request.body)) {
      inputBuffer = request.body;
    } else if (typeof request.body === 'string') {
      inputBuffer = Buffer.from(request.body, 'utf8');
    } else if (request.body && typeof request.body === 'object') {
      if (Buffer.isBuffer(request.body.content)) {
        inputBuffer = request.body.content;
      } else {
        const text = request.body.content || request.body.log || request.body.text || '';
        inputBuffer = Buffer.from(text, 'utf8');
      }
    }

    if (!inputBuffer || inputBuffer.length === 0) {
      return reply.code(400).send({
        error: 'No log content received. Usage: gzip -c access.log | curl -F "file=@-" <URL>/api/ingest',
      });
    }

    const isGzip = (inputBuffer.length >= 2 && inputBuffer[0] === 0x1f && inputBuffer[1] === 0x8b);
    let compressedBuffer = null;
    let compressedSize = 0;
    let decompressedSize = 0;
    let lineCount = 0;

    if (isGzip) {
      if (inputBuffer.length > MAX_COMPRESSED_BYTES) {
        return reply.code(413).send({
          error: `Compressed log size (${Math.round(inputBuffer.length / (1024 * 1024))} MB) exceeds the ${Math.round(MAX_COMPRESSED_BYTES / (1024 * 1024))} MB limit.`,
        });
      }
      compressedBuffer = inputBuffer;
      compressedSize = inputBuffer.length;
      // Extract decompressed size from gzip footer (RFC 1952 ISIZE) without allocating heap in Node
      decompressedSize = inputBuffer.length >= 8 ? inputBuffer.readUInt32LE(inputBuffer.length - 4) : 0;
      if (decompressedSize === 0) {
        decompressedSize = compressedSize;
      }
      if (decompressedSize > MAX_DECOMPRESSED_BYTES) {
        return reply.code(413).send({
          error: `Uncompressed log size (${Math.round(decompressedSize / (1024 * 1024))} MB) exceeds the ${Math.round(MAX_DECOMPRESSED_BYTES / (1024 * 1024))} MB limit. Browser memory cannot process logs larger than 2 GB.`,
        });
      }
      lineCount = 0; // Browser worker computes exact lines during client-side stream decompression
    } else {
      if (inputBuffer.length > MAX_RAW_INGEST_BYTES) {
        return reply.code(413).send({
          error: `Uncompressed log size (${Math.round(inputBuffer.length / (1024 * 1024))} MB) exceeds the ${Math.round(MAX_RAW_INGEST_BYTES / (1024 * 1024))} MB limit. Please compress before sending: gzip -c access.log | curl -F "file=@-" <URL>/api/ingest`,
        });
      }
      // Plain text: count lines and compress to gzip for storage and network transfer
      decompressedSize = inputBuffer.length;
      for (let i = 0; i < inputBuffer.length; i++) {
        if (inputBuffer[i] === 10) lineCount++;
      }
      if (inputBuffer.length > 0 && inputBuffer[inputBuffer.length - 1] !== 10) lineCount++;

      compressedBuffer = await gzipAsync(inputBuffer);
      compressedSize = compressedBuffer.length;
    }

    const sessionId = crypto.randomBytes(12).toString('hex');
    const now = Date.now();
    const expiresAt = now + SESSION_TTL_MS;

    // Upload to R2 ephemeral storage
    const r2Key = `ephemeral/${sessionId}.log.gz`;

    try {
      await r2Storage.uploadLog(r2Key, compressedBuffer, {
        'session-id': sessionId,
        'line-count': String(lineCount),
        'decompressed-size': String(decompressedSize),
      });

      ephemeralSessions.set(sessionId, {
        r2Key,
        compressedSize,
        decompressedSize,
        lineCount,
        createdAt: now,
        expiresAt,
      });
    } catch (err) {
      fastify.log.error('Failed to upload to R2:', err);
      return reply.code(500).send({ error: 'Failed to upload log to storage.' });
    }

    compressedBuffer = null;
    inputBuffer = null;

    const baseUrl = getPublicBaseUrl(request);
    const viewUrl = `${baseUrl}/nginx?session=${sessionId}`;

    const userAgent = (request.headers['user-agent'] || '').toLowerCase();
    const acceptHeader = (request.headers['accept'] || '').toLowerCase();

    // If request is from cURL or terminal client, return friendly formatted text (unless JSON requested)
    if (!acceptHeader.includes('application/json') && (userAgent.includes('curl') || userAgent.includes('wget') || userAgent.includes('httpie') || acceptHeader === 'text/plain')) {
      reply.type('text/plain');
      return `\n🚀 Nginx Log Analysis Ready!\n\n👉 View Dashboard: ${viewUrl}\n\nℹ️  Note: This link is valid for 10 minutes and is automatically deleted upon first viewing.\n\n`;
    }

    return {
      success: true,
      sessionId,
      url: viewUrl,
      expiresAt: new Date(expiresAt).toISOString(),
    };
  });

  // GET /api/ingest/:sessionId/meta — Get size/line metadata without consuming the session
  fastify.get('/ingest/:sessionId/meta', async (request, reply) => {
    const { sessionId } = request.params;
    const session = ephemeralSessions.get(sessionId);
    if (!session || session.purged || session.consumed || session.chunks?.get('chunk-1')?.status === 'consumed' || Date.now() > session.expiresAt) {
      return reply.code(404).send({ error: 'Session not found or expired.' });
    }
    return {
      success: true,
      decompressedSize: session.decompressedSize || 0,
      lineCount: session.lineCount || 0,
      compressedSize: session.compressedSize || 0,
      expiresAt: new Date(session.expiresAt).toISOString(),
    };
  });

  // GET /api/ingest/:sessionId — Stream compressed gzip file directly from R2
  fastify.get('/ingest/:sessionId', async (request, reply) => {
    const { sessionId } = request.params;
    if (!sessionId || !ephemeralSessions.has(sessionId)) {
      return reply.code(404).send({
        error: 'Session not found or expired. Logs are automatically purged after 10 minutes or upon first viewing.',
      });
    }

    const session = ephemeralSessions.get(sessionId);
    if (session.purged || session.consumed || session.chunks?.get('chunk-1')?.status === 'consumed') {
      return reply.code(404).send({
        error: 'Session not found or expired. Logs are automatically purged after 10 minutes or upon first viewing.',
      });
    }
    if (Date.now() > session.expiresAt) {
      ephemeralSessions.delete(sessionId);
      if (session.r2Key && r2Storage.isEnabled()) {
        r2Storage.deleteLog(session.r2Key).catch(() => {});
      }
      return reply.code(410).send({ error: 'Session has expired.' });
    }

    const r2Key = session.r2Key;
    const lineCount = session.lineCount || 0;
    const decompressedSize = session.decompressedSize || 0;
    const compressedSize = session.compressedSize || 0;

    // In multi-node architecture, keep session alive in ephemeralSessions for 15 minutes
    // so subsequent nodes can push chunks to the active session.
    if (session.chunks?.has('chunk-1')) {
      session.chunks.get('chunk-1').status = 'consumed';
    }
    session.consumed = true;
    session.expiresAt = Date.now() + MULTI_NODE_TTL_MS;
    consumedSessions.set(sessionId, Date.now());

    try {
      if (!r2Storage.isEnabled()) {
        return reply.code(503).send({ error: 'Storage service is not configured.' });
      }

      // Generate presigned download URL (1 hour expiry) and redirect
      const downloadUrl = await r2Storage.generatePresignedDownloadUrl(r2Key, 3600);

      // Set headers for browser decompression
      reply.header('X-Log-Compressed', 'true');
      reply.header('X-Log-Compressed-Size', String(compressedSize));
      reply.header('X-Log-Decompressed-Size', String(decompressedSize));
      reply.header('X-Log-Line-Count', String(lineCount));
      reply.header('X-Download-URL', downloadUrl);
      reply.header('Access-Control-Expose-Headers', 'Content-Length, Content-Encoding, X-Log-Compressed, X-Log-Compressed-Size, X-Log-Decompressed-Size, X-Log-Line-Count, X-Download-URL');

      // Redirect to R2 presigned URL (browser downloads directly from R2)
      return reply.code(302).redirect(downloadUrl);

    } catch (err) {
      fastify.log.error(`Error generating download URL: ${err.message}`);
      return reply.code(500).send({ error: 'Failed to retrieve session data.' });
    }
  });

  // POST /api/ingest/:sessionId/purge — Delete the R2 object after a completed download.
  // The client calls this once it has fully read the log, honouring delete-on-first-view.
  // Idempotent: a second call is a no-op, and an unknown session is simply reported gone.
  fastify.post('/ingest/:sessionId/purge', async (request, reply) => {
    const { sessionId } = request.params;
    if (!sessionId) {
      return reply.code(400).send({ error: 'Missing sessionId.' });
    }

    if (!consumedSessions.has(sessionId)) {
      return { success: true, purged: false };
    }
    consumedSessions.delete(sessionId);

    if (!r2Storage.isEnabled()) {
      return { success: true, purged: false };
    }

    try {
      const session = ephemeralSessions.get(sessionId);
      if (session) {
        session.purged = true;
        session.consumed = true;
        if (session.chunks?.has('chunk-1')) {
          const c1 = session.chunks.get('chunk-1');
          c1.status = 'consumed';
          await r2Storage.deleteLog(c1.r2Key).catch(() => {});
        }
        if (session.r2Key) {
          await r2Storage.deleteLog(session.r2Key).catch(() => {});
          session.r2Key = null;
        }
      } else {
        await r2Storage.deleteLog(`ephemeral/${sessionId}.log.gz`).catch(() => {});
      }
      fastify.log.info(`🧹 Purged ephemeral session ${sessionId} from R2 after first view`);
      return { success: true, purged: true };
    } catch (err) {
      // R2 is eventually consistent on delete; a miss here is not user-visible.
      fastify.log.warn(`Purge of ephemeral session ${sessionId} failed: ${err.message}`);
      return { success: true, purged: false };
    }
  });

  // GET /api/ingest/:sessionId/queue — Return pending FIFO queue chunks
  fastify.get('/ingest/:sessionId/queue', async (request, reply) => {
    const { sessionId } = request.params;
    const session = ephemeralSessions.get(sessionId);
    if (!session || Date.now() > session.expiresAt) {
      return reply.code(404).send({ error: 'Session not found or expired.' });
    }

    const pendingChunks = [];
    if (session.chunks) {
      for (const chunk of session.chunks.values()) {
        if (chunk.status === 'pending' && chunk.chunkId !== 'chunk-1') {
          pendingChunks.push({
            chunkId: chunk.chunkId,
            compressedSize: chunk.compressedSize,
            decompressedSize: chunk.decompressedSize,
            lineCount: chunk.lineCount,
            uploadedAt: chunk.uploadedAt,
          });
        }
      }
    }
    // FIFO sort: oldest upload first
    pendingChunks.sort((a, b) => a.uploadedAt - b.uploadedAt);

    return {
      success: true,
      sessionId,
      chunks: pendingChunks,
    };
  });

  // GET /api/ingest/:sessionId/chunk/:chunkId — Presigned download URL for chunk
  fastify.get('/ingest/:sessionId/chunk/:chunkId', async (request, reply) => {
    const { sessionId, chunkId } = request.params;
    const session = ephemeralSessions.get(sessionId);
    if (!session || Date.now() > session.expiresAt) {
      return reply.code(404).send({ error: 'Session not found or expired.' });
    }
    const chunk = session.chunks?.get(chunkId);
    if (!chunk) {
      return reply.code(404).send({ error: 'Chunk not found.' });
    }
    if (!r2Storage.isEnabled()) {
      return reply.code(503).send({ error: 'Storage service is not configured.' });
    }

    const downloadUrl = await r2Storage.generatePresignedDownloadUrl(chunk.r2Key, 3600);
    return {
      success: true,
      sessionId,
      chunkId,
      downloadUrl,
      compressedSize: chunk.compressedSize,
      decompressedSize: chunk.decompressedSize,
      lineCount: chunk.lineCount,
    };
  });

  // POST /api/ingest/:sessionId/chunk/:chunkId/purge — Purge chunk after browser consumed it
  fastify.post('/ingest/:sessionId/chunk/:chunkId/purge', async (request, reply) => {
    const { sessionId, chunkId } = request.params;
    const session = ephemeralSessions.get(sessionId);
    if (!session) {
      return { success: true, purged: false };
    }
    const chunk = session.chunks?.get(chunkId);
    if (!chunk) {
      return { success: true, purged: false };
    }

    chunk.status = 'consumed';
    if (r2Storage.isEnabled()) {
      await r2Storage.deleteLog(chunk.r2Key).catch(() => {});
    }
    return { success: true, purged: true };
  });

  // POST /api/ingest/:sessionId/chunk/:chunkId/discard — Discard chunk without merging
  fastify.post('/ingest/:sessionId/chunk/:chunkId/discard', async (request, reply) => {
    const { sessionId, chunkId } = request.params;
    const session = ephemeralSessions.get(sessionId);
    if (!session) {
      return { success: true, discarded: false };
    }
    const chunk = session.chunks?.get(chunkId);
    if (chunk) {
      session.chunks.delete(chunkId);
      if (r2Storage.isEnabled()) {
        await r2Storage.deleteLog(chunk.r2Key).catch(() => {});
      }
    }
    return { success: true, discarded: true };
  });

  // POST /api/ingest/:sessionId/heartbeat — Renew session TTL
  fastify.post('/ingest/:sessionId/heartbeat', async (request, reply) => {
    const { sessionId } = request.params;
    const session = ephemeralSessions.get(sessionId);
    if (!session || Date.now() > session.expiresAt) {
      return reply.code(404).send({ error: 'Session not found or expired.' });
    }
    session.expiresAt = Date.now() + MULTI_NODE_TTL_MS;
    return {
      success: true,
      sessionId,
      expiresAt: new Date(session.expiresAt).toISOString(),
    };
  });

  // POST /api/ingest/:sessionId/destroy — Destroy session and all chunks
  fastify.post('/ingest/:sessionId/destroy', async (request, reply) => {
    const { sessionId } = request.params;
    const session = ephemeralSessions.get(sessionId);
    if (session) {
      ephemeralSessions.delete(sessionId);
      if (r2Storage.isEnabled()) {
        if (session.chunks) {
          for (const chunk of session.chunks.values()) {
            r2Storage.deleteLog(chunk.r2Key).catch(() => {});
          }
        }
        if (session.r2Key) {
          r2Storage.deleteLog(session.r2Key).catch(() => {});
        }
      }
    }
    return { success: true, destroyed: true };
  });
}
