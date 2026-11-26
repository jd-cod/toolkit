/**
 * Share System Routes — Fastify + MySQL + R2 Storage
 *
 * POST /api/share              → Create a Traffic Analyzer share (log stored in R2)
 * POST /api/share/snapshot     → Create a snapshot share for any other tool
 * GET  /api/share/:code        → Get share metadata
 * POST /api/share/:code/verify → Verify password + return data/download URL
 *
 * Traffic Analyzer shares live in `shares` and point at an R2 object. Every
 * other tool stores a JSON snapshot of its result in `tool_shares`.
 */

import r2Storage from '../lib/r2-storage.js';
import {
  SNAPSHOT_TOOLS,
  SHARE_CODE_RE,
  generateShareCode,
  hashSharePassword,
  isExpired,
  readSharePassword,
  resolveExpiry,
  toMySQLDatetime,
  verifySharePassword,
} from '../lib/share-utils.js';

const SNAPSHOT_BODY_LIMIT = 25 * 1024 * 1024;
const MAX_TITLE_LENGTH = 200;
const MAX_SUBJECT_LENGTH = 255;
const MAX_CHECKED_AT_LENGTH = 50;
const MAX_SOURCE_URL_LENGTH = 2000;

// Password guesses are the only expensive thing an anonymous caller can do here.
const VERIFY_RATE_LIMIT = { max: 10, timeWindow: '1 minute' };

function readTitle(value, fallback) {
  const title = typeof value === 'string' ? value.trim() : '';
  return (title || fallback).slice(0, MAX_TITLE_LENGTH);
}

function readSourceUrl(value) {
  if (typeof value !== 'string') return null;
  const url = value.trim();
  if (!url || url.length > MAX_SOURCE_URL_LENGTH) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? url : null;
  } catch {
    return null;
  }
}

function parseSnapshot(dataJson) {
  return typeof dataJson === 'string' ? JSON.parse(dataJson) : dataJson;
}

export default async function shareRoutes(fastify, opts) {
  const pool = fastify.mysql;

  async function codeExists(code) {
    const [shareRows] = await pool.execute('SELECT 1 FROM shares WHERE code = ?', [code]);
    if (shareRows.length > 0) return true;
    const [toolRows] = await pool.execute('SELECT 1 FROM tool_shares WHERE code = ?', [code]);
    return toolRows.length > 0;
  }

  async function generateUniqueCode() {
    for (let attempt = 0; attempt < 10; attempt++) {
      const candidate = generateShareCode(8);
      if (!(await codeExists(candidate))) return candidate;
    }
    return '';
  }

  async function getShareRecord(code) {
    if (!SHARE_CODE_RE.test(code || '')) return null;

    const [shareRows] = await pool.execute(
      'SELECT code, title, r2_key, source_url, password_hash, expires_at, created_at, r2_uploaded_at FROM shares WHERE code = ?', [code]
    );
    if (shareRows.length > 0) return { share_type: 'nginx', ...shareRows[0] };

    const [toolRows] = await pool.execute(
      'SELECT code, tool_key, title, subject, password_hash, expires_at, created_at, checked_at_utc, data_json FROM tool_shares WHERE code = ?', [code]
    );
    if (toolRows.length > 0) return { share_type: toolRows[0].tool_key, ...toolRows[0] };

    return null;
  }

  /** Validates the options every share has in common: expiry and password. */
  async function readShareOptions(body) {
    const expiry = resolveExpiry(body.expiry);
    if (!expiry.ok) return { error: expiry.error };
    const password = readSharePassword(body.password);
    if (!password.ok) return { error: password.error };
    return {
      expiresAt: expiry.expiresAt,
      expiresAtIso: expiry.expiresAtIso,
      passwordHash: password.password ? await hashSharePassword(password.password) : null,
    };
  }

  // POST /api/share — Create a Traffic Analyzer share for a log already uploaded to R2
  fastify.post('/share', async (request, reply) => {
    const body = request.body || {};
    const shareCode = typeof body.shareCode === 'string' ? body.shareCode.trim() : '';

    if (!SHARE_CODE_RE.test(shareCode)) {
      return reply.code(400).send({ success: false, error: 'Missing or invalid shareCode. Please upload the log first via /api/storage/upload.' });
    }

    // The object key is derived from the code, never taken from the caller: a
    // caller-supplied key would let anyone mint a public link to another
    // share's log and walk around its password.
    const r2Key = `shares/${shareCode}.log.gz`;
    if (typeof body.r2_key === 'string' && body.r2_key.trim() && body.r2_key.trim() !== r2Key) {
      return reply.code(400).send({ success: false, error: 'r2_key does not match shareCode.' });
    }

    const options = await readShareOptions(body);
    if (options.error) return reply.code(400).send({ success: false, error: options.error });

    if (await codeExists(shareCode)) {
      return reply.code(409).send({ success: false, error: 'A share already exists for this upload.' });
    }

    const title = readTitle(body.title, 'Untitled Analysis');
    const sourceUrl = readSourceUrl(body.source_url);
    const now = toMySQLDatetime(new Date());

    await pool.execute(
      'INSERT INTO shares (code, title, r2_key, source_url, password_hash, expires_at, created_at, r2_uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [shareCode, title, r2Key, sourceUrl, options.passwordHash, options.expiresAt, now, now]
    );

    return { success: true, code: shareCode, url: `/s/${shareCode}`, r2_key: r2Key, source_url: sourceUrl, expires_at: options.expiresAtIso, has_password: !!options.passwordHash };
  });

  // POST /api/share/snapshot — Create a snapshot share for any registered tool
  fastify.post('/share/snapshot', { bodyLimit: SNAPSHOT_BODY_LIMIT }, async (request, reply) => {
    const body = request.body || {};
    const tool = typeof body.tool === 'string' ? body.tool.trim().toLowerCase() : '';

    if (!Object.hasOwn(SNAPSHOT_TOOLS, tool)) {
      return reply.code(400).send({ success: false, error: 'Unknown or missing tool.' });
    }

    const subject = typeof body.subject === 'string' ? body.subject.trim() : '';
    if (!subject) return reply.code(400).send({ success: false, error: 'Missing subject.' });
    if (subject.length > MAX_SUBJECT_LENGTH) return reply.code(400).send({ success: false, error: 'Subject is too long.' });

    const snapshot = body.snapshot;
    if (!snapshot || typeof snapshot !== 'object') {
      return reply.code(400).send({ success: false, error: 'Missing snapshot payload.' });
    }

    let checkedAtUTC = typeof body.checked_at_utc === 'string' ? body.checked_at_utc.trim() : '';
    if (checkedAtUTC.length > MAX_CHECKED_AT_LENGTH) {
      return reply.code(400).send({ success: false, error: 'Invalid checked_at_utc timestamp.' });
    }
    if (!checkedAtUTC) checkedAtUTC = new Date().toISOString();

    const options = await readShareOptions(body);
    if (options.error) return reply.code(400).send({ success: false, error: options.error });

    const code = await generateUniqueCode();
    if (!code) return reply.code(500).send({ success: false, error: 'Could not generate unique code. Try again.' });

    const title = readTitle(body.title, `${SNAPSHOT_TOOLS[tool]} Snapshot`);

    await pool.execute(
      'INSERT INTO tool_shares (code, tool_key, title, subject, password_hash, expires_at, created_at, checked_at_utc, data_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [code, tool, title, subject, options.passwordHash, options.expiresAt, toMySQLDatetime(new Date()), checkedAtUTC, JSON.stringify(snapshot)]
    );

    return { success: true, code, url: `/s/${code}`, expires_at: options.expiresAtIso, has_password: !!options.passwordHash };
  });

  // GET /api/share/:code — Get share metadata
  // SECURITY: If password-protected, only return minimal metadata.
  // The R2 download URL / snapshot data is only available after password verification via POST /verify.
  fastify.get('/share/:code', async (request, reply) => {
    const row = await getShareRecord(request.params.code);
    if (!row) return reply.code(404).send({ error: 'Share not found.' });
    if (isExpired(row.expires_at)) return reply.code(410).send({ error: 'This share link has expired.' });

    // If password-protected, only return metadata needed for the password prompt
    if (row.password_hash) {
      return {
        share_type: row.share_type,
        title: row.title,
        has_password: true,
        password_required: true,
        expires_at: row.expires_at,
        created_at: row.created_at,
      };
    }

    const response = {
      share_type: row.share_type,
      title: row.title,
      has_password: false,
      expires_at: row.expires_at,
      created_at: row.created_at,
      subject: row.subject || '',
      checked_at_utc: row.checked_at_utc || '',
    };

    // For nginx shares, add R2 download URL
    if (row.share_type === 'nginx' && row.r2_key) {
      try {
        const downloadUrl = await r2Storage.generatePresignedDownloadUrl(row.r2_key, 3600);
        response.download_url = downloadUrl;
        response.r2_key = row.r2_key;
        response.source_url = row.source_url || '';
      } catch (err) {
        fastify.log.error('Failed to generate download URL:', err);
      }
    }

    return response;
  });

  // POST /api/share/:code/verify — Verify password + return data/download URL
  fastify.post('/share/:code/verify', { config: { rateLimit: VERIFY_RATE_LIMIT } }, async (request, reply) => {
    const row = await getShareRecord(request.params.code);
    if (!row) return reply.code(404).send({ error: 'Share not found.' });
    if (isExpired(row.expires_at)) return reply.code(410).send({ error: 'This share link has expired.' });

    if (row.password_hash) {
      const submitted = readSharePassword(request.body?.password);
      if (!submitted.ok || !submitted.password) {
        return reply.code(401).send({ error: 'Password required.', needs_password: true });
      }
      if (!(await verifySharePassword(submitted.password, row.password_hash))) {
        return reply.code(401).send({ error: 'Incorrect password.', needs_password: true });
      }
    }

    if (row.share_type === 'nginx') {
      if (!row.r2_key) return reply.code(404).send({ error: 'Invalid share type or missing data.' });
      try {
        const downloadUrl = await r2Storage.generatePresignedDownloadUrl(row.r2_key, 3600);
        return {
          share_type: 'nginx',
          title: row.title,
          expires_at: row.expires_at,
          created_at: row.created_at,
          download_url: downloadUrl,
          r2_key: row.r2_key,
          source_url: row.source_url || '',
        };
      } catch (err) {
        fastify.log.error('Failed to generate download URL:', err);
        return reply.code(500).send({ error: 'Failed to generate download URL.' });
      }
    }

    let snapshot;
    try {
      snapshot = parseSnapshot(row.data_json);
    } catch {
      return reply.code(500).send({ error: 'Stored snapshot is unreadable.' });
    }

    return {
      share_type: row.share_type,
      title: row.title,
      subject: row.subject || '',
      expires_at: row.expires_at,
      created_at: row.created_at,
      checked_at_utc: row.checked_at_utc,
      snapshot,
    };
  });
}
