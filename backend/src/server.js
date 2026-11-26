/**
 * SysAdmin Toolkit — Fastify API Server
 *
 * Entrypoint for the backend API. Registers plugins (MySQL, Auth, CORS, Cookie)
 * and all API route modules.
 *
 * Replaces: Cloudflare Workers + Hono.js (src/index.js)
 *
 * Start:
 *   Development: npm run dev
 *   Production:  npm start
 */

import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';

// Plugins
import mysqlPlugin from './plugins/mysql.js';
import authPlugin from './plugins/auth.js';
import { initGeoIpDataRefresh } from './lib/geoip-data.js';
import { initIP2LocationDataRefresh } from './lib/ip2location-data.js';
import { initBotIpRefresh } from './lib/bot-ip-updater.js';
import { initCleanupScheduler } from './lib/cleanup-scheduler.js';
import r2Storage from './lib/r2-storage.js';

// Routes
import abuseRoutes from './routes/abuse.js';
import asnRoutes from './routes/asn.js';
import dnsRoutes from './routes/dns.js';
import storageRoutes from './routes/storage.js';
import ipinfoRoutes from './routes/ipinfo.js';
import myipRoutes from './routes/myip.js';
import sslRoutes from './routes/ssl.js';
import shareRoutes from './routes/share.js';
import adminRoutes from './routes/admin.js';
import publicRoutes from './routes/public.js';
import whoisRoutes from './routes/whois.js';
import ingestRoutes from './routes/ingest.js';
import { initGeoIPReaders } from './lib/geoip-city.js';

// Create Fastify instance
const fastify = Fastify({
  bodyLimit: 25 * 1024 * 1024,
  logger: {
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    transport: process.env.NODE_ENV !== 'production'
      ? { target: 'pino-pretty', options: { colorize: true } }
      : undefined,
  },
});

// ─── Register Plugins ───

// CORS — allow all origins during dev, restrict in production
await fastify.register(cors, {
  origin: process.env.NODE_ENV === 'production'
    ? process.env.CORS_ORIGIN || true
    : true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
});

// Cookie parser (needed for JWT auth via cookies)
await fastify.register(cookie);

// Rate limiting
await fastify.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  allowList: (request) => {
    // Internal loopback SSR requests from Next.js on the same container/server
    const isLoopback = request.ip === '127.0.0.1' || request.ip === '::1';
    const hasExternalForward = Boolean(request.headers['x-forwarded-for'] || request.headers['x-real-ip']);
    return isLoopback && !hasExternalForward;
  },
  keyGenerator: (request) => {
    return request.headers['x-forwarded-for']?.split(',')[0]?.trim()
      || request.headers['x-real-ip']
      || request.ip;
  },
});

// Cache-Control header for all API responses
fastify.addHook('onSend', async (request, reply, payload) => {
  reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  return payload;
});

// MySQL connection pool
await fastify.register(mysqlPlugin);

// Auth (bcrypt + JWT)
await fastify.register(authPlugin);

// ─── Bootstrap Admin User ───

async function bootstrapAdmin() {
  try {
    const [rows] = await fastify.mysql.execute('SELECT COUNT(*) as cnt FROM admin_users');
    if (rows[0].cnt === 0) {
      const username = process.env.ADMIN_BOOTSTRAP_USERNAME || 'admin';
      const password = process.env.ADMIN_BOOTSTRAP_PASSWORD;
      if (password) {
        const hash = await fastify.auth.hashPassword(password);
        await fastify.mysql.execute(
          'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
          [username, hash]
        );
        fastify.log.info(`✅ Admin user "${username}" bootstrapped successfully`);
      } else {
        fastify.log.warn('⚠️  No ADMIN_BOOTSTRAP_PASSWORD set — skipping admin bootstrap');
      }
    }
  } catch (err) {
    fastify.log.error(`Admin bootstrap failed: ${err.message}`);
  }
}

// ─── Register API Routes ───

// All routes are registered under /api prefix
await fastify.register(abuseRoutes, { prefix: '/api' });
await fastify.register(asnRoutes, { prefix: '/api' });
await fastify.register(dnsRoutes, { prefix: '/api' });
await fastify.register(storageRoutes, { prefix: '/api' }); // R2 storage routes (replaces gist)
await fastify.register(ipinfoRoutes, { prefix: '/api' });
await fastify.register(myipRoutes, { prefix: '/api' });
await fastify.register(sslRoutes, { prefix: '/api' });
await fastify.register(shareRoutes, { prefix: '/api' });
await fastify.register(adminRoutes, { prefix: '/api' });
await fastify.register(publicRoutes, { prefix: '/api' });
await fastify.register(whoisRoutes, { prefix: '/api' });
await fastify.register(ingestRoutes, { prefix: '/api' });
await fastify.register(ingestRoutes); // Also register at root so /ingest works directly

fastify.get('/api/health', async (request, reply) => {
  try {
    const [rows] = await fastify.mysql.execute('SELECT 1 as ok');
    return { status: 'ok', database: 'connected', timestamp: new Date().toISOString() };
  } catch (err) {
    return reply.code(500).send({ status: 'error', database: 'disconnected', error: err.message });
  }
});

// ─── Global Error Handler ───

fastify.setErrorHandler((error, request, reply) => {
  fastify.log.error(error);
  const statusCode = error.statusCode || 500;
  reply.code(statusCode).send({
    error: error.message || 'Internal server error.',
    statusCode,
  });
});

// ─── Start Server ───

const PORT = parseInt(process.env.PORT || '4000', 10);
const HOST = process.env.HOST || '0.0.0.0';

try {
  // Bootstrap admin and GeoIP data before server starts
  await bootstrapAdmin();
  await initGeoIpDataRefresh(fastify);
  await initIP2LocationDataRefresh(fastify);
  await initGeoIPReaders(fastify.log);
  await initBotIpRefresh(fastify);

  // Expired shares are cleaned up whether or not R2 is configured
  initCleanupScheduler(fastify.mysql);
  if (r2Storage.isEnabled()) {
    fastify.log.info('✅ R2 storage and cleanup scheduler initialized');
  } else {
    fastify.log.warn('⚠️  R2 storage not configured - storage features disabled');
  }

  await fastify.listen({ port: PORT, host: HOST });
  fastify.log.info(`🚀 SysAdmin Toolkit API running on http://${HOST}:${PORT}`);
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}

export default fastify;
