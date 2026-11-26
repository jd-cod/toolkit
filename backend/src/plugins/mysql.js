/**
 * MySQL Connection Pool Plugin for Fastify
 * 
 * Registers a mysql2 connection pool as `fastify.mysql`.
 * Uses pool.execute() for prepared statements (auto-releases connections).
 * 
 * Usage in routes:
 *   const [rows] = await fastify.mysql.execute('SELECT * FROM table WHERE id = ?', [id]);
 *   const row = rows[0]; // single row
 */

import fp from 'fastify-plugin';
import mysql from 'mysql2/promise';

async function mysqlPlugin(fastify, opts) {
  const pool = mysql.createPool({
    host: opts.host || process.env.DB_HOST || '127.0.0.1',
    port: parseInt(opts.port || process.env.DB_PORT || '3306', 10),
    user: opts.user || process.env.DB_USER || 'sysadmin_app',
    password: opts.password || process.env.DB_PASSWORD || '',
    database: opts.database || process.env.DB_NAME || 'sysadmin_toolkit',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 10000,
    // MySQL 8.4 defaults
    charset: 'utf8mb4',
    timezone: '+00:00',
  });

  // Test connection on startup
  try {
    const connection = await pool.getConnection();
    fastify.log.info('✅ MySQL connected successfully');
    connection.release();
  } catch (err) {
    fastify.log.error(`❌ MySQL connection failed: ${err.message}`);
    throw err;
  }

  // Decorate fastify instance
  fastify.decorate('mysql', pool);

  // Close pool on shutdown
  fastify.addHook('onClose', async () => {
    await pool.end();
    fastify.log.info('MySQL pool closed');
  });
}

export default fp(mysqlPlugin, {
  name: 'mysql',
  fastify: '5.x',
});
