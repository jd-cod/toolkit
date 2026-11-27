/**
 * SMTP session probe for the SMTP Server Test tool.
 *
 * Opens a session, reads the banner, sends EHLO, upgrades with STARTTLS when
 * offered, and quits. It never sends MAIL FROM, RCPT TO or DATA: no message
 * is sent and no open-relay test is made, so the tool cannot be used to
 * deliver or probe mail on someone else's server.
 */

import net from 'node:net';
import tls from 'node:tls';
import os from 'node:os';
import { assertAllowedHost, guardedLookup } from './net-guard.js';

export const SMTP_PORTS = [25, 465, 587, 2525];
const MAX_TRANSCRIPT_LINES = 80;
const MAX_LINE_LENGTH = 1000;

export function heloName() {
  const configured = String(process.env.SMTP_TEST_HELO || '').trim();
  if (/^[a-z0-9.-]{1,253}$/i.test(configured)) return configured;
  const host = os.hostname();
  return /^[a-z0-9.-]{1,253}$/i.test(host) && host.includes('.') ? host : 'smtp-test.invalid';
}

/** Reads SMTP replies (possibly multi-line) from a socket. */
function createReplyReader(socket, transcript) {
  let buffer = '';
  let pending = null;
  let failure = null;
  const lines = [];

  function flush() {
    if (!pending) return;
    // A reply ends at the first line of the form "NNN text" (space, not dash).
    const end = lines.findIndex(line => /^\d{3}(?: |$)/.test(line));
    if (end !== -1) {
      const reply = lines.splice(0, end + 1);
      const { resolve } = pending;
      pending = null;
      resolve({ code: Number(reply[end].slice(0, 3)), lines: reply.map(line => line.slice(4)) });
    } else if (failure) {
      const { reject } = pending;
      pending = null;
      reject(failure);
    }
  }

  function onData(chunk) {
    buffer += chunk.toString('latin1');
    if (buffer.length > 64 * 1024) { failure = new Error('Server sent too much data.'); socket.destroy(); }
    let index;
    while ((index = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, index).replace(/\r$/, '').slice(0, MAX_LINE_LENGTH);
      buffer = buffer.slice(index + 1);
      lines.push(line);
      if (transcript.length < MAX_TRANSCRIPT_LINES) transcript.push({ from: 'server', line });
    }
    flush();
  }
  function onEnd(err) {
    failure = failure || (err instanceof Error ? err : new Error('Connection closed by the server.'));
    flush();
  }

  socket.on('data', onData);
  socket.on('error', onEnd);
  socket.on('close', () => onEnd());

  return {
    read(timeoutMs) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { pending = null; reject(new Error('Timed out waiting for the server.')); }, timeoutMs);
        pending = {
          resolve: value => { clearTimeout(timer); resolve(value); },
          reject: err => { clearTimeout(timer); reject(err); },
        };
        flush();
      });
    },
    detach() {
      socket.off('data', onData);
      socket.off('error', onEnd);
    },
  };
}

function send(socket, transcript, line) {
  if (transcript.length < MAX_TRANSCRIPT_LINES) transcript.push({ from: 'client', line });
  socket.write(`${line}\r\n`);
}

/**
 * Servers greet EHLO with the caller's address ("at your service,
 * [198.51.100.7]"). Shown to a visitor, that would publish the address this
 * toolkit connects from, which may be an origin hidden behind a CDN.
 */
export function redactGreeting(transcript) {
  for (let i = 0; i < transcript.length - 1; i++) {
    if (transcript[i].from !== 'client' || !/^EHLO /.test(transcript[i].line)) continue;
    const reply = transcript[i + 1];
    if (reply.from !== 'server') continue;
    const match = /^(\d{3}[- ]\S+)(.*)$/.exec(reply.line);
    if (match && match[2].trim()) reply.line = `${match[1]} [greeting hidden]`;
  }
  return transcript;
}

function parseExtensions(lines) {
  const extensions = lines.slice(1).map(line => line.trim()).filter(Boolean);
  const find = name => extensions.find(ext => ext.toUpperCase() === name || ext.toUpperCase().startsWith(`${name} `) || ext.toUpperCase().startsWith(`${name}=`));
  const auth = find('AUTH');
  const size = find('SIZE');
  return {
    extensions,
    starttls: Boolean(find('STARTTLS')),
    auth_mechanisms: auth ? auth.slice(4).trim().split(/\s+/).filter(Boolean) : [],
    size_limit: size && /^\d+$/.test(size.slice(4).trim()) ? Number(size.slice(4).trim()) : null,
    pipelining: Boolean(find('PIPELINING')),
    eightbitmime: Boolean(find('8BITMIME')),
    smtputf8: Boolean(find('SMTPUTF8')),
  };
}

function describeTls(socket, host) {
  const cert = socket.getPeerCertificate();
  const hasCert = cert && Object.keys(cert).length > 0;
  const validTo = hasCert ? new Date(cert.valid_to) : null;
  const mismatch = hasCert ? tls.checkServerIdentity(host, cert) : null;
  return {
    protocol: socket.getProtocol() || '',
    cipher: socket.getCipher()?.name || '',
    trusted: socket.authorized === true,
    trust_error: socket.authorized ? '' : String(socket.authorizationError || ''),
    certificate: hasCert ? {
      subject: cert.subject?.CN || '',
      issuer: cert.issuer?.O || cert.issuer?.CN || '',
      valid_from: cert.valid_from || '',
      valid_to: cert.valid_to || '',
      days_remaining: validTo && !Number.isNaN(validTo.getTime()) ? Math.floor((validTo.getTime() - Date.now()) / 86400000) : null,
      names: String(cert.subjectaltname || '').split(', ').filter(name => name.startsWith('DNS:')).map(name => name.slice(4)).slice(0, 30),
      hostname_match: !mismatch,
    } : null,
  };
}

function openSocket({ host, port, implicitTls, timeoutMs, lookup }) {
  return new Promise((resolve, reject) => {
    const options = { host, port, lookup };
    const socket = implicitTls
      ? tls.connect({ ...options, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false })
      : net.connect(options);
    const timer = setTimeout(() => { socket.destroy(); reject(Object.assign(new Error('Connection timed out.'), { code: 'ETIMEDOUT' })); }, timeoutMs);
    socket.once(implicitTls ? 'secureConnect' : 'connect', () => { clearTimeout(timer); resolve(socket); });
    socket.once('error', err => { clearTimeout(timer); reject(err); });
  });
}

function upgradeToTls(socket, host, timeoutMs) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({ socket, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false });
    const timer = setTimeout(() => { secure.destroy(); reject(new Error('TLS handshake timed out.')); }, timeoutMs);
    secure.once('secureConnect', () => { clearTimeout(timer); resolve(secure); });
    secure.once('error', err => { clearTimeout(timer); reject(err); });
  });
}

/**
 * @returns {Promise<object>} never rejects; failures are reported in `error`.
 */
export async function probeSmtp({ host, port = 25, timeoutMs = 8000, lookup = guardedLookup, helo = heloName() }) {
  const started = Date.now();
  const transcript = [];
  const result = {
    host, port, address: '', connected: false, implicit_tls: port === 465,
    banner: '', banner_host: '', ehlo: null, starttls: { offered: false, upgraded: false, error: '' },
    tls: null, post_tls_ehlo: null, timings: { connect_ms: null, banner_ms: null, total_ms: 0 },
    transcript, error: '', error_code: '',
  };
  let socket = null;

  try {
    assertAllowedHost(host);
    socket = await openSocket({ host, port, implicitTls: result.implicit_tls, timeoutMs, lookup });
    result.connected = true;
    result.address = socket.remoteAddress || '';
    result.timings.connect_ms = Date.now() - started;
    if (result.implicit_tls) result.tls = describeTls(socket, host);

    let reader = createReplyReader(socket, transcript);
    const banner = await reader.read(timeoutMs);
    result.timings.banner_ms = Date.now() - started;
    result.banner = banner.lines.join(' ').slice(0, 300);
    result.banner_host = (banner.lines[0] || '').split(/\s+/)[0] || '';
    if (banner.code !== 220) throw new Error(`Server greeted with ${banner.code} instead of 220.`);

    send(socket, transcript, `EHLO ${helo}`);
    const ehlo = await reader.read(timeoutMs);
    if (ehlo.code !== 250) throw new Error(`EHLO was refused with ${ehlo.code}.`);
    result.ehlo = parseExtensions(ehlo.lines);
    result.starttls.offered = result.ehlo.starttls;

    if (!result.implicit_tls && result.ehlo.starttls) {
      send(socket, transcript, 'STARTTLS');
      const reply = await reader.read(timeoutMs);
      if (reply.code === 220) {
        try {
          reader.detach();
          socket = await upgradeToTls(socket, host, timeoutMs);
          result.starttls.upgraded = true;
          result.tls = describeTls(socket, host);
          reader = createReplyReader(socket, transcript);
          send(socket, transcript, `EHLO ${helo}`);
          const secureEhlo = await reader.read(timeoutMs);
          if (secureEhlo.code === 250) result.post_tls_ehlo = parseExtensions(secureEhlo.lines);
        } catch (err) {
          result.starttls.error = err.message;
        }
      } else {
        result.starttls.error = `STARTTLS was refused with ${reply.code}.`;
      }
    }

    if (!socket.destroyed) {
      send(socket, transcript, 'QUIT');
      await reader.read(2000).catch(() => {});
    }
  } catch (err) {
    result.error = err?.message || 'Connection failed.';
    result.error_code = err?.code || '';
  } finally {
    socket?.destroy();
    redactGreeting(transcript);
    result.timings.total_ms = Date.now() - started;
  }
  return result;
}

const finding = (severity, title, detail = '') => ({ severity, title, detail });

/** Turns a probe result into findings. `ptr` is the reverse DNS of the server address, when known. */
export function smtpFindings(probe, { ptr = [] } = {}) {
  const findings = [];
  if (!probe.connected) {
    if (probe.error_code === 'EBLOCKEDDESTINATION') return [finding('critical', 'Destination is not a public address', 'Only servers on the public internet can be tested.')];
    const blocked = probe.port === 25 && ['ETIMEDOUT', 'ENETUNREACH', 'EHOSTUNREACH'].includes(probe.error_code);
    return [finding('critical', `Could not connect to port ${probe.port}`, blocked
      ? `${probe.error} Many hosting providers block outbound port 25, so this can come from the network this toolkit runs on and not from the mail server.`
      : probe.error)];
  }
  if (probe.error) findings.push(finding('critical', 'The SMTP session failed', probe.error));
  else findings.push(finding('ok', 'Server accepted the connection', `Banner: ${probe.banner}`));

  const encrypted = Boolean(probe.tls);
  if (!probe.implicit_tls && probe.ehlo) {
    if (!probe.starttls.offered) findings.push(finding('warning', 'STARTTLS is not offered', 'Mail to and from this server travels unencrypted. Enable TLS on the server.'));
    else if (!probe.starttls.upgraded) findings.push(finding('critical', 'STARTTLS is offered but the upgrade failed', probe.starttls.error));
  }

  if (encrypted) {
    const { protocol, certificate, trusted, trust_error: trustError } = probe.tls;
    if (['TLSv1', 'TLSv1.1', 'SSLv3'].includes(protocol)) findings.push(finding('warning', `Connection uses ${protocol}`, 'TLS 1.0 and 1.1 are deprecated. Allow TLS 1.2 or newer.'));
    else findings.push(finding('ok', `Encrypted with ${protocol}`, probe.tls.cipher));
    if (!certificate) {
      findings.push(finding('warning', 'Server presented no certificate', ''));
    } else {
      if (certificate.days_remaining !== null && certificate.days_remaining < 0) findings.push(finding('critical', 'Certificate has expired', `It expired on ${certificate.valid_to}.`));
      else if (certificate.days_remaining !== null && certificate.days_remaining < 14) findings.push(finding('warning', `Certificate expires in ${certificate.days_remaining} days`, 'Renew it soon.'));
      if (!certificate.hostname_match) findings.push(finding('warning', `Certificate does not match ${probe.host}`, `It is issued for ${certificate.names.slice(0, 4).join(', ') || certificate.subject || 'another name'}. Senders that enforce MTA-STS or DANE will refuse to deliver.`));
      if (!trusted && certificate.days_remaining !== null && certificate.days_remaining >= 0) findings.push(finding('warning', 'Certificate is not trusted', `${trustError || 'The chain could not be verified.'} Most senders still deliver, but senders that enforce MTA-STS will not.`));
    }
  }

  if (!probe.implicit_tls && probe.ehlo?.auth_mechanisms.length > 0) {
    findings.push(finding('warning', 'AUTH is offered before encryption', `The server advertises ${probe.ehlo.auth_mechanisms.join(', ')} on the unencrypted session, so passwords can be sent in clear text. Offer AUTH only after STARTTLS.`));
  }

  if (probe.address) {
    const names = ptr.map(name => name.toLowerCase().replace(/\.$/, ''));
    if (names.length === 0) findings.push(finding('warning', `No reverse DNS for ${probe.address}`, 'Many receivers reject mail from servers without a PTR record.'));
    else if (probe.banner_host && !names.includes(probe.banner_host.toLowerCase())) findings.push(finding('info', 'Banner name differs from reverse DNS', `The banner says ${probe.banner_host}, reverse DNS says ${names[0]}. Matching names help deliverability.`));
  }
  if (probe.timings.banner_ms !== null && probe.timings.banner_ms > 5000) findings.push(finding('info', `Banner took ${(probe.timings.banner_ms / 1000).toFixed(1)} seconds`, 'Some servers delay the banner on purpose to slow down spam bots.'));
  return findings;
}
