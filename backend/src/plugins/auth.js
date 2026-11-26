/**
 * Auth Plugin for Fastify
 *
 * Provides:
 *   - fastify.auth.hashPassword(password) — bcrypt hash
 *   - fastify.auth.verifyPassword(password, hash) — bcrypt compare
 *   - fastify.auth.createToken(payload) — JWT sign
 *   - fastify.auth.verifyToken(token) — JWT verify
 *   - fastify.auth.authMiddleware — preHandler hook for protected routes
 *
 * Replaces CF Workers PBKDF2 + manual HMAC-SHA256 JWT with bcrypt + jsonwebtoken.
 */

import fp from 'fastify-plugin';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const BCRYPT_ROUNDS = 10;
const JWT_EXPIRES_IN = '72h'; // Same as original: 72-hour admin sessions

async function authPlugin(fastify, opts) {
  const jwtSecret = process.env.ADMIN_JWT_SECRET;

  if (!jwtSecret) {
    fastify.log.warn('⚠️  ADMIN_JWT_SECRET not set — auth will fail');
  }

  const auth = {
    /**
     * Hash a password with bcrypt.
     */
    async hashPassword(password) {
      return bcrypt.hash(password, BCRYPT_ROUNDS);
    },

    /**
     * Compare a password against a bcrypt hash.
     */
    async verifyPassword(password, hash) {
      return bcrypt.compare(password, hash);
    },

    /**
     * Create a JWT token.
     * @param {object} payload - Data to include in token (e.g. { username })
     * @returns {string} JWT token string
     */
    createToken(payload) {
      return jwt.sign(payload, jwtSecret, { expiresIn: JWT_EXPIRES_IN });
    },

    /**
     * Verify and decode a JWT token.
     * @param {string} token
     * @returns {object|null} Decoded payload or null if invalid
     */
    verifyToken(token) {
      try {
        return jwt.verify(token, jwtSecret);
      } catch {
        return null;
      }
    },

    /**
     * Fastify preHandler hook — verifies admin JWT from cookie.
     * Sets request.admin = decoded payload.
     *
     * Usage:
     *   fastify.get('/endpoint', { preHandler: [fastify.auth.authMiddleware] }, handler)
     */
    async authMiddleware(request, reply) {
      const cookie = request.cookies?.admin_token;
      if (!cookie) {
        return reply.code(401).send({ error: 'Unauthorized' });
      }

      if (!jwtSecret) {
        fastify.log.error('ADMIN_JWT_SECRET not configured');
        return reply.code(500).send({ error: 'Server misconfigured' });
      }

      const payload = auth.verifyToken(cookie);
      if (!payload) {
        return reply.code(401).send({ error: 'Invalid or expired token' });
      }

      request.admin = payload;
    },
  };

  fastify.decorate('auth', auth);
}

export default fp(authPlugin, {
  name: 'auth',
  dependencies: ['@fastify/cookie'],
  fastify: '5.x',
});
