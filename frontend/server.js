const { createServer } = require('http');
const { parse } = require('url');
const next = require('next');
const { createAccessGate } = require('./access-gate');

const dev = process.env.NODE_ENV !== 'production';
const hostname = process.env.HOSTNAME || '0.0.0.0';
const port = parseInt(process.env.FRONTEND_PORT || process.env.PORT || '3000', 10);

const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();
const accessGate = createAccessGate({
  apiBase: process.env.BACKEND_API_URL || 'http://127.0.0.1:4000/api',
});

app.prepare().then(() => {
  createServer(async (req, res) => {
    try {
      // Next.js forwards request headers to the backend but does not add the
      // address that connected to it. Appending it here, like any reverse
      // proxy, gives the backend one X-Forwarded-For entry it can trust for
      // rate limiting; entries the client sent stay to its left and are
      // ignored there (backend/src/lib/client-ip.js).
      const peer = req.socket.remoteAddress;
      if (peer) {
        const prior = req.headers['x-forwarded-for'];
        req.headers['x-forwarded-for'] = prior ? `${prior}, ${peer}` : peer;
      }

      // Invite-only mode: visitors who are not allowed get the gate page.
      const gate = await accessGate.check(req);
      if (gate) {
        res.writeHead(gate.status, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Robots-Tag': 'noindex',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'SAMEORIGIN',
        });
        res.end(req.method === 'HEAD' ? undefined : gate.html);
        return;
      }

      const parsedUrl = parse(req.url, true);
      await handle(req, res, parsedUrl);
    } catch (err) {
      console.error('Error handling request:', err);
      res.statusCode = 500;
      res.end('Internal Server Error');
    }
  }).listen(port, hostname, (err) => {
    if (err) throw err;
    console.log(`> Frontend server ready on http://${hostname}:${port}`);
  });
}).catch((err) => {
  console.error('Failed to prepare Next.js app:', err);
  process.exit(1);
});
