/**
 * Share System Routes — Fastify + MySQL + R2 Storage
 *
 * POST /api/share           → Create a shareable link with R2 storage
 * POST /api/share/dns       → Create DNS snapshot share
 * GET  /api/share/:code     → Get share metadata
 * POST /api/share/:code/verify → Verify password + return data/download URL
 *
 * Uses Cloudflare R2 for log storage instead of GitHub Gist.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcrypt';
import r2Storage from '../lib/r2-storage.js';
import { str, httpUrl } from '../lib/input.js';
import { bruteForceLimit } from '../lib/client-ip.js';

const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function generateCode(length = 8) {
  const bytes = randomBytes(length);
  return Array.from(bytes, b => CHARS[b % CHARS.length]).join('');
}

const SHARE_CODE = /^[A-Za-z0-9]{8}$/;
const SHARE_R2_KEY = /^shares\/([A-Za-z0-9]{8})\.log\.gz$/;
const CREATE_RATE_LIMIT = { max: 20, timeWindow: '1 minute' };
const VERIFY_RATE_LIMIT = bruteForceLimit(20, '1 minute');

function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

/**
 * Shares created before bcrypt was introduced store an unsalted SHA-256 hex
 * digest; those still verify, compared in constant time. Everything newer
 * (including shares created from the admin panel) is a bcrypt hash.
 */
async function verifySharePassword(submitted, storedHash) {
  if (typeof storedHash !== 'string' || !storedHash) return false;
  if (storedHash.startsWith('$2')) return bcrypt.compare(submitted, storedHash);
  const expected = Buffer.from(storedHash, 'utf8');
  const actual = Buffer.from(createHash('sha256').update(submitted).digest('hex'), 'utf8');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/** Format a Date as MySQL-compatible 'YYYY-MM-DD HH:MM:SS' in UTC */
function toMySQLDatetime(date) {
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

function computeExpiry(expiry) {
  const now = new Date();
  if (expiry === '24h') return toMySQLDatetime(new Date(now.getTime() + 24 * 60 * 60 * 1000));
  if (expiry === '7d')  return toMySQLDatetime(new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000));
  if (expiry === '30d') return toMySQLDatetime(new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000));
  return null;
}

function isExpired(expiresAt) {
  if (!expiresAt) return false;
  return new Date() > new Date(expiresAt);
}

export default async function shareRoutes(fastify, opts) {
  const pool = fastify.mysql;

  async function generateUniqueCode() {
    for (let attempt = 0; attempt < 10; attempt++) {
      const candidate = generateCode(8);
      const [shareRows] = await pool.execute('SELECT 1 FROM shares WHERE code = ?', [candidate]);
      if (shareRows.length > 0) continue;
      const [dnsRows] = await pool.execute('SELECT 1 FROM dns_shares WHERE code = ?', [candidate]);
      if (dnsRows.length > 0) continue;
      const [whoisRows] = await pool.execute('SELECT 1 FROM whois_shares WHERE code = ?', [candidate]);
      if (whoisRows.length > 0) continue;
      const [myipRows] = await pool.execute('SELECT 1 FROM myip_shares WHERE code = ?', [candidate]);
      if (myipRows.length > 0) continue;
      const [asnRows] = await pool.execute('SELECT 1 FROM asn_shares WHERE code = ?', [candidate]);
      if (asnRows.length === 0) return candidate;
    }
    return '';
  }

  async function getShareRecord(code) {
    const [shareRows] = await pool.execute(
      'SELECT code, title, r2_key, source_url, password_hash, expires_at, created_at, r2_uploaded_at FROM shares WHERE code = ?', [code]
    );
    if (shareRows.length > 0) return { share_type: 'nginx', ...shareRows[0] };

    const [dnsRows] = await pool.execute(
      'SELECT code, title, domain, password_hash, expires_at, created_at, checked_at_utc, data_json FROM dns_shares WHERE code = ?', [code]
    );
    if (dnsRows.length > 0) return { share_type: 'dns', ...dnsRows[0] };

    const [whoisRows] = await pool.execute(
      'SELECT code, title, domain, password_hash, expires_at, created_at, checked_at_utc, data_json FROM whois_shares WHERE code = ?', [code]
    );
    if (whoisRows.length > 0) return { share_type: 'whois', ...whoisRows[0] };

    const [myipRows] = await pool.execute(
      'SELECT code, title, ip, password_hash, expires_at, created_at, checked_at_utc, data_json FROM myip_shares WHERE code = ?', [code]
    );
    if (myipRows.length > 0) return { share_type: 'myip', ...myipRows[0] };

    const [asnRows] = await pool.execute(
      'SELECT code, title, asn, password_hash, expires_at, created_at, checked_at_utc, data_json FROM asn_shares WHERE code = ?', [code]
    );
    if (asnRows.length > 0) return { share_type: 'asn', ...asnRows[0] };

    return null;
  }

  // POST /api/share — Create nginx share with R2 storage
  fastify.post('/share', { bodyLimit: 25 * 1024 * 1024, config: { rateLimit: CREATE_RATE_LIMIT } }, async (request, reply) => {
    const body = request.body || {};
    const title = str(body.title, 'Untitled Analysis').trim() || 'Untitled Analysis';
    const r2Key = str(body.r2_key).trim(); // R2 object key from storage upload
    const shareCode = str(body.shareCode).trim(); // Share code from storage upload
    const sourceUrl = httpUrl(body.source_url); // Optional: original external URL
    const expiry = body.expiry || 'never';
    const password = str(body.password).trim();

    if (!r2Key && !shareCode) {
      return reply.code(400).send({ success: false, error: 'Missing r2_key or shareCode. Please upload the log first via /api/storage/upload.' });
    }

    // A share may only point at the object its own upload created
    // (shares/<code>.log.gz), under that upload's code. Accepting any key, or a
    // fresh code for an existing key, would let a caller attach a new
    // password-free share to someone else's stored log.
    let code = shareCode;
    if (r2Key) {
      const match = SHARE_R2_KEY.exec(r2Key);
      if (!match || (shareCode && shareCode !== match[1])) {
        return reply.code(400).send({ success: false, error: 'Invalid r2_key or shareCode. Please upload the log again via /api/storage/upload.' });
      }
      code = match[1];
    } else if (!SHARE_CODE.test(shareCode)) {
      return reply.code(400).send({ success: false, error: 'Invalid shareCode. Please upload the log again via /api/storage/upload.' });
    }

    const expiresAt = computeExpiry(expiry);
    const passwordHash = password ? await hashPassword(password) : null;
    const createdAt = toMySQLDatetime(new Date());
    const uploadedAt = toMySQLDatetime(new Date());

    // Construct R2 key if not provided
    const finalR2Key = r2Key || `shares/${code}.log.gz`;

    try {
      await pool.execute(
        'INSERT INTO shares (code, title, r2_key, source_url, password_hash, expires_at, created_at, r2_uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [code, title, finalR2Key, sourceUrl || null, passwordHash, expiresAt, createdAt, uploadedAt]
      );
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return reply.code(409).send({ success: false, error: 'A share link already exists for this upload.' });
      }
      throw err;
    }

    return { success: true, code, url: `/s/${code}`, r2_key: finalR2Key, source_url: sourceUrl || null };
  });

  // POST /api/share/dns — Create DNS snapshot share
  fastify.post('/share/dns', { bodyLimit: 25 * 1024 * 1024, config: { rateLimit: CREATE_RATE_LIMIT } }, async (request, reply) => {
    const body = request.body || {};
    const title = str(body.title, 'DNS Snapshot').trim() || 'DNS Snapshot';
    const domain = str(body.domain).trim().toLowerCase();
    const expiry = body.expiry || 'never';
    const password = str(body.password).trim();
    const checkedAtUTC = str(body.checked_at_utc).trim();
    const snapshot = body.snapshot;

    if (!domain) return reply.code(400).send({ success: false, error: 'Missing domain.' });
    if (!checkedAtUTC) return reply.code(400).send({ success: false, error: 'Missing checked_at_utc timestamp.' });
    if (!snapshot || typeof snapshot !== 'object') return reply.code(400).send({ success: false, error: 'Missing DNS snapshot payload.' });

    const code = await generateUniqueCode();
    if (!code) return reply.code(500).send({ success: false, error: 'Could not generate unique code. Try again.' });

    const expiresAt = computeExpiry(expiry);
    const passwordHash = password ? await hashPassword(password) : null;
    const createdAt = toMySQLDatetime(new Date());

    await pool.execute(
      'INSERT INTO dns_shares (code, title, domain, password_hash, expires_at, created_at, checked_at_utc, data_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [code, title, domain, passwordHash, expiresAt, createdAt, checkedAtUTC, JSON.stringify(snapshot)]
    );

    return { success: true, code, url: `/s/${code}` };
  });

  // POST /api/share/whois — Create WHOIS snapshot share
  fastify.post('/share/whois', { bodyLimit: 25 * 1024 * 1024, config: { rateLimit: CREATE_RATE_LIMIT } }, async (request, reply) => {
    const body = request.body || {};
    const title = str(body.title, 'WHOIS Snapshot').trim() || 'WHOIS Snapshot';
    const domain = str(body.domain).trim().toLowerCase();
    const expiry = body.expiry || 'never';
    const password = str(body.password).trim();
    const checkedAtUTC = str(body.checked_at_utc).trim();
    const snapshot = body.snapshot;

    if (!domain) return reply.code(400).send({ success: false, error: 'Missing domain.' });
    if (!checkedAtUTC) return reply.code(400).send({ success: false, error: 'Missing checked_at_utc timestamp.' });
    if (!snapshot || typeof snapshot !== 'object') return reply.code(400).send({ success: false, error: 'Missing WHOIS snapshot payload.' });

    const code = await generateUniqueCode();
    if (!code) return reply.code(500).send({ success: false, error: 'Could not generate unique code. Try again.' });

    const expiresAt = computeExpiry(expiry);
    const passwordHash = password ? await hashPassword(password) : null;
    const createdAt = toMySQLDatetime(new Date());

    await pool.execute(
      'INSERT INTO whois_shares (code, title, domain, password_hash, expires_at, created_at, checked_at_utc, data_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [code, title, domain, passwordHash, expiresAt, createdAt, checkedAtUTC, JSON.stringify(snapshot)]
    );

    return { success: true, code, url: `/s/${code}` };
  });

  // POST /api/share/myip — Create MyIP snapshot share
  fastify.post('/share/myip', { bodyLimit: 25 * 1024 * 1024, config: { rateLimit: CREATE_RATE_LIMIT } }, async (request, reply) => {
    const body = request.body || {};
    const title = str(body.title, 'My IP Snapshot').trim() || 'My IP Snapshot';
    const ip = str(body.ip).trim();
    const expiry = body.expiry || 'never';
    const password = str(body.password).trim();
    const checkedAtUTC = str(body.checked_at_utc).trim();
    const snapshot = body.snapshot;

    if (!ip) return reply.code(400).send({ success: false, error: 'Missing IP address.' });
    if (!checkedAtUTC) return reply.code(400).send({ success: false, error: 'Missing checked_at_utc timestamp.' });
    if (!snapshot || typeof snapshot !== 'object') return reply.code(400).send({ success: false, error: 'Missing MyIP snapshot payload.' });

    const code = await generateUniqueCode();
    if (!code) return reply.code(500).send({ success: false, error: 'Could not generate unique code. Try again.' });

    const expiresAt = computeExpiry(expiry);
    const passwordHash = password ? await hashPassword(password) : null;
    const createdAt = toMySQLDatetime(new Date());

    await pool.execute(
      'INSERT INTO myip_shares (code, title, ip, password_hash, expires_at, created_at, checked_at_utc, data_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [code, title, ip, passwordHash, expiresAt, createdAt, checkedAtUTC, JSON.stringify(snapshot)]
    );

    return { success: true, code, url: `/s/${code}` };
  });

  // POST /api/share/asn — Create ASN snapshot share
  fastify.post('/share/asn', { bodyLimit: 25 * 1024 * 1024, config: { rateLimit: CREATE_RATE_LIMIT } }, async (request, reply) => {
    const body = request.body || {};
    const title = str(body.title, 'ASN Snapshot').trim() || 'ASN Snapshot';
    const asn = (body.asn || '').toString().trim().toUpperCase();
    const expiry = body.expiry || 'never';
    const password = str(body.password).trim();
    const checkedAtUTC = str(body.checked_at_utc).trim();
    const snapshot = body.snapshot;

    if (!asn) return reply.code(400).send({ success: false, error: 'Missing ASN.' });
    if (!checkedAtUTC) return reply.code(400).send({ success: false, error: 'Missing checked_at_utc timestamp.' });
    if (!snapshot || typeof snapshot !== 'object') return reply.code(400).send({ success: false, error: 'Missing ASN snapshot payload.' });

    const code = await generateUniqueCode();
    if (!code) return reply.code(500).send({ success: false, error: 'Could not generate unique code. Try again.' });

    const expiresAt = computeExpiry(expiry);
    const passwordHash = password ? await hashPassword(password) : null;
    const createdAt = toMySQLDatetime(new Date());

    await pool.execute(
      'INSERT INTO asn_shares (code, title, asn, password_hash, expires_at, created_at, checked_at_utc, data_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [code, title, asn, passwordHash, expiresAt, createdAt, checkedAtUTC, JSON.stringify(snapshot)]
    );

    return { success: true, code, url: `/s/${code}` };
  });

  // GET /api/share/:code — Get share metadata
  // SECURITY: If password-protected, only return minimal metadata.
  // The R2 download URL / DNS data is only available after password verification via POST /verify.
  fastify.get('/share/:code', async (request, reply) => {
    const row = await getShareRecord(request.params.code);
    if (!row) return reply.code(404).send({ error: 'Share not found.' });
    if (isExpired(row.expires_at)) return reply.code(410).send({ error: 'This share link has expired.' });

    const hasPassword = !!row.password_hash;

    // If password-protected, only return metadata needed for the password prompt
    if (hasPassword) {
      return {
        share_type: row.share_type,
        title: row.title,
        has_password: true,
        password_required: true,
        expires_at: row.expires_at,
        created_at: row.created_at,
      };
    }

    // No password — return full metadata
    const response = {
      share_type: row.share_type,
      title: row.title,
      has_password: false,
      expires_at: row.expires_at,
      created_at: row.created_at,
      domain: row.domain || '',
      ip: row.ip || '',
      asn: row.asn || '',
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
      const body = request.body || {};
      const submitted = str(body.password).trim();
      if (!submitted) return reply.code(401).send({ error: 'Password required.', needs_password: true });
      if (!(await verifySharePassword(submitted, row.password_hash))) {
        return reply.code(401).send({ error: 'Incorrect password.', needs_password: true });
      }
    }

    if (row.share_type === 'dns') {
      return {
        share_type: 'dns', title: row.title, domain: row.domain,
        checked_at_utc: row.checked_at_utc,
        snapshot: typeof row.data_json === 'string' ? JSON.parse(row.data_json) : row.data_json,
      };
    }

    if (row.share_type === 'whois') {
      return {
        share_type: 'whois', title: row.title, domain: row.domain,
        checked_at_utc: row.checked_at_utc,
        snapshot: typeof row.data_json === 'string' ? JSON.parse(row.data_json) : row.data_json,
      };
    }

    if (row.share_type === 'myip') {
      return {
        share_type: 'myip', title: row.title, ip: row.ip,
        checked_at_utc: row.checked_at_utc,
        snapshot: typeof row.data_json === 'string' ? JSON.parse(row.data_json) : row.data_json,
      };
    }

    if (row.share_type === 'asn') {
      return {
        share_type: 'asn', title: row.title, asn: row.asn,
        checked_at_utc: row.checked_at_utc,
        snapshot: typeof row.data_json === 'string' ? JSON.parse(row.data_json) : row.data_json,
      };
    }

    // Nginx share - return R2 presigned download URL
    if (row.share_type === 'nginx' && row.r2_key) {
      try {
        const downloadUrl = await r2Storage.generatePresignedDownloadUrl(row.r2_key, 3600);
        return {
          share_type: 'nginx',
          title: row.title,
          download_url: downloadUrl,
          r2_key: row.r2_key,
          source_url: row.source_url || '',
        };
      } catch (err) {
        fastify.log.error('Failed to generate download URL:', err);
        return reply.code(500).send({ error: 'Failed to generate download URL.' });
      }
    }

    return reply.code(404).send({ error: 'Invalid share type or missing data.' });
  });
}
