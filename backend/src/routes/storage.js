/**
 * Storage Routes — R2 Direct Upload/Download
 *
 * POST /api/storage/init-upload      → Get presigned upload URL for direct client→R2 upload
 * POST /api/storage/complete-upload  → Complete upload and create share record
 * GET  /api/storage/download/:code   → Get presigned download URL for R2 object
 * POST /api/storage/upload-external  → Download from external URL and upload to R2
 *
 * Direct Upload Flow (bandwidth optimization):
 *   1. Client requests presigned upload URL from server
 *   2. Client uploads directly to R2 (bypassing server bandwidth)
 *   3. Client notifies server of completion
 *   4. Server creates metadata and share record
 */

import r2Storage from '../lib/r2-storage.js';
import { guardedRequest } from '../lib/net-guard.js';
import zlib from 'node:zlib';
import { promisify } from 'node:util';

const gzipAsync = promisify(zlib.gzip);
const gunzipAsync = promisify(zlib.gunzip);
const MAX_UPLOAD_SIZE = 400 * 1024 * 1024; // 400 MB
// Ceiling for decompressing an upload to count its lines; a larger result is a
// decompression bomb or more than the browser can analyse anyway.
const MAX_DECOMPRESSED_SIZE = 2048 * 1024 * 1024; // 2 GB
const SHARE_CODE = /^[A-Za-z0-9]{8}$/;
// These endpoints accept large bodies or make the server fetch a remote file,
// so they get a tighter per-client limit than the global one.
const UPLOAD_RATE_LIMIT = { max: 10, timeWindow: '1 minute' };

/**
 * Check if content is already gzipped
 */
function isGzipped(buffer) {
  return buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b;
}

/**
 * Count lines in a buffer
 */
function countLines(buffer) {
  let count = 0;
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] === 10) count++; // newline character
  }
  // Add 1 if file doesn't end with newline
  if (buffer.length > 0 && buffer[buffer.length - 1] !== 10) count++;
  return count;
}

export default async function storageRoutes(fastify, opts) {
  if (!r2Storage.isEnabled()) {
    fastify.log.warn('R2 storage is not configured. Storage routes will return 503.');
  }

  // GET /api/storage/download/:code — Get presigned download URL
  fastify.get('/storage/download/:code', async (request, reply) => {
    if (!r2Storage.isEnabled()) {
      return reply.code(503).send({ error: 'Storage service is not configured.' });
    }

    const { code } = request.params;
    if (!SHARE_CODE.test(code)) {
      return reply.code(400).send({ error: 'Invalid share code.' });
    }

    // A code that already belongs to a share must go through
    // /api/share/:code (and /verify), which enforce its password and expiry.
    // Only fresh uploads that have not been turned into a share are served here.
    const [shareRows] = await fastify.mysql.execute(
      'SELECT password_hash, expires_at FROM shares WHERE code = ?', [code]
    );
    if (shareRows.length > 0) {
      const share = shareRows[0];
      if (share.expires_at && new Date() > new Date(share.expires_at)) {
        return reply.code(410).send({ error: 'This share link has expired.' });
      }
      if (share.password_hash) {
        return reply.code(401).send({ error: 'This share is password-protected.', needs_password: true });
      }
    }

    const r2Key = `shares/${code}.log.gz`;

    try {
      // Generate presigned download URL (1 hour expiry)
      const downloadUrl = await r2Storage.generatePresignedDownloadUrl(r2Key, 3600);

      return {
        success: true,
        downloadUrl,
        expiresIn: 3600, // 1 hour
      };
    } catch (err) {
      fastify.log.error('Failed to generate download URL:', err);
      return reply.code(500).send({ error: 'Failed to generate download URL.' });
    }
  });

  // POST /api/storage/upload — Direct server-side upload (for small content or backward compatibility)
  fastify.post('/storage/upload', {
    bodyLimit: MAX_UPLOAD_SIZE + 10 * 1024 * 1024,
    config: { rateLimit: UPLOAD_RATE_LIMIT },
  }, async (request, reply) => {
    if (!r2Storage.isEnabled()) {
      return reply.code(503).send({ error: 'Storage service is not configured.' });
    }

    const body = request.body || {};
    const content = typeof body.content === 'string' ? body.content : '';

    if (!content || content.length === 0) {
      return reply.code(400).send({ error: 'No content provided.' });
    }

    try {
      // Convert content to buffer
      let inputBuffer = Buffer.from(content, 'utf8');

      if (inputBuffer.length > MAX_UPLOAD_SIZE) {
        return reply.code(413).send({ error: 'Content exceeds 400 MB limit.' });
      }

      // Compress if not already compressed
      let compressedBuffer;
      let decompressedSize;
      let lineCount;

      if (isGzipped(inputBuffer)) {
        compressedBuffer = inputBuffer;
        try {
          const decompressed = await gunzipAsync(inputBuffer, { maxOutputLength: MAX_DECOMPRESSED_SIZE });
          decompressedSize = decompressed.length;
          lineCount = countLines(decompressed);
        } catch (err) {
          decompressedSize = inputBuffer.length;
          lineCount = 0;
        }
      } else {
        decompressedSize = inputBuffer.length;
        lineCount = countLines(inputBuffer);
        compressedBuffer = await gzipAsync(inputBuffer);
      }

      // Generate unique share code
      const shareCode = r2Storage.generateShareCode();
      const r2Key = `shares/${shareCode}.log.gz`;

      // Upload to R2
      await r2Storage.uploadLog(r2Key, compressedBuffer, {
        'line-count': String(lineCount),
        'decompressed-size': String(decompressedSize),
      });

      // Store metadata
      const metadata = {
        shareCode,
        compressedSize: compressedBuffer.length,
        decompressedSize,
        lineCount,
        createdAt: new Date().toISOString(),
      };

      await r2Storage.uploadMetadata(`${r2Key}.metadata.json`, metadata);

      return {
        success: true,
        shareCode,
        r2Key,
        compressedSize: compressedBuffer.length,
        decompressedSize,
        lineCount,
      };
    } catch (err) {
      fastify.log.error('Upload failed:', err);
      return reply.code(500).send({ error: `Upload failed: ${err.message}` });
    }
  });

  // POST /api/storage/upload-external — Download from external URL and upload to R2
  fastify.post('/storage/upload-external', { config: { rateLimit: UPLOAD_RATE_LIMIT } }, async (request, reply) => {
    if (!r2Storage.isEnabled()) {
      return reply.code(503).send({ error: 'Storage service is not configured.' });
    }

    const body = request.body || {};
    const sourceUrl = typeof body.url === 'string' ? body.url.trim() : '';

    if (!sourceUrl) {
      return reply.code(400).send({ error: 'No source URL provided.' });
    }

    try {
      // Fetch content from the external URL. guardedRequest only reaches
      // public http(s) hosts, re-checks every redirect, and stops reading at
      // the size limit instead of buffering an unbounded response.
      let response;
      try {
        response = await guardedRequest(sourceUrl, {
          headers: {
            'User-Agent': 'SysAdmin-Toolkit/2.0 (Log Analyzer)',
            'Accept': 'text/plain, application/octet-stream, */*',
          },
          timeoutMs: 30000, // 30s timeout
          maxBytes: MAX_UPLOAD_SIZE,
        });
      } catch (err) {
        if (err.code === 'ERESPONSETOOLARGE') {
          return reply.code(413).send({ error: 'External content exceeds 400 MB limit.' });
        }
        if (err.statusCode === 400) {
          return reply.code(400).send({ error: `Cannot fetch this URL: ${err.message}` });
        }
        throw err;
      }

      if (response.status < 200 || response.status >= 300) {
        return reply.code(response.status >= 400 ? response.status : 502).send({ error: `Failed to fetch URL: HTTP ${response.status}` });
      }

      // Read content
      const inputBuffer = response.body;

      // Compress if needed
      let compressedBuffer;
      let decompressedSize;
      let lineCount;

      if (isGzipped(inputBuffer)) {
        compressedBuffer = inputBuffer;
        try {
          const decompressed = await gunzipAsync(inputBuffer, { maxOutputLength: MAX_DECOMPRESSED_SIZE });
          decompressedSize = decompressed.length;
          lineCount = countLines(decompressed);
        } catch (err) {
          decompressedSize = inputBuffer.length;
          lineCount = 0;
        }
      } else {
        decompressedSize = inputBuffer.length;
        lineCount = countLines(inputBuffer);
        compressedBuffer = await gzipAsync(inputBuffer);
      }

      // Generate unique share code
      const shareCode = r2Storage.generateShareCode();
      const r2Key = `shares/${shareCode}.log.gz`;

      // Upload to R2
      await r2Storage.uploadLog(r2Key, compressedBuffer, {
        'line-count': String(lineCount),
        'decompressed-size': String(decompressedSize),
        'source-url': sourceUrl,
      });

      // Store metadata
      const metadata = {
        shareCode,
        compressedSize: compressedBuffer.length,
        decompressedSize,
        lineCount,
        sourceUrl,
        createdAt: new Date().toISOString(),
      };

      await r2Storage.uploadMetadata(`${r2Key}.metadata.json`, metadata);

      return {
        success: true,
        shareCode,
        r2Key,
        compressedSize: compressedBuffer.length,
        decompressedSize,
        lineCount,
        sourceUrl,
      };
    } catch (err) {
      fastify.log.error('External upload failed:', err);
      return reply.code(500).send({ error: `External upload failed: ${err.message}` });
    }
  });
}
