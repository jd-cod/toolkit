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
import zlib from 'node:zlib';
import { promisify } from 'node:util';

const gzipAsync = promisify(zlib.gzip);
const gunzipAsync = promisify(zlib.gunzip);
const MAX_UPLOAD_SIZE = 400 * 1024 * 1024; // 400 MB

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
  fastify.post('/storage/upload', { bodyLimit: MAX_UPLOAD_SIZE + 10 * 1024 * 1024 }, async (request, reply) => {
    if (!r2Storage.isEnabled()) {
      return reply.code(503).send({ error: 'Storage service is not configured.' });
    }

    const body = request.body || {};
    const content = body.content || '';

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
          const decompressed = await gunzipAsync(inputBuffer);
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
  fastify.post('/storage/upload-external', async (request, reply) => {
    if (!r2Storage.isEnabled()) {
      return reply.code(503).send({ error: 'Storage service is not configured.' });
    }

    const body = request.body || {};
    const sourceUrl = (body.url || '').trim();

    if (!sourceUrl) {
      return reply.code(400).send({ error: 'No source URL provided.' });
    }

    try {
      // Fetch content from external URL (with timeout)
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout

      const response = await fetch(sourceUrl, {
        headers: {
          'User-Agent': 'SysAdmin-Toolkit/2.0 (Log Analyzer)',
          'Accept': 'text/plain, application/octet-stream, */*',
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        return reply.code(response.status).send({ error: `Failed to fetch URL: HTTP ${response.status}` });
      }

      // Read content
      const arrayBuffer = await response.arrayBuffer();
      const inputBuffer = Buffer.from(arrayBuffer);

      if (inputBuffer.length > MAX_UPLOAD_SIZE) {
        return reply.code(413).send({ error: 'External content exceeds 400 MB limit.' });
      }

      // Compress if needed
      let compressedBuffer;
      let decompressedSize;
      let lineCount;

      if (isGzipped(inputBuffer)) {
        compressedBuffer = inputBuffer;
        try {
          const decompressed = await gunzipAsync(inputBuffer);
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
