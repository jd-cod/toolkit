import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { Resolver } from 'node:dns/promises';
import { parseCertTime } from './oracle';

/**
 * A second, independent source for live SSL checks: the test process opens
 * its own TLS connection to the host and reads the certificate with Node's
 * `tls` and `crypto` modules. Nothing here goes through the application.
 */

export interface ProbedCert {
  subject: string;
  subjectOrg: string;
  issuer: string;
  issuerOrg: string;
  selfIssued: boolean;
  validFromMs: number;
  validToMs: number;
  keyType: string;
  keyBits: number;
}

export interface TlsFacts {
  ok: true;
  leaf: ProbedCert;
  /** Every subject alternative name, in certificate order; DNS names bare, others as `IP Address:...`. */
  sans: string[];
  serial: string;
  fingerprint256: string;
  /** `TLS 1.3` */
  protocol: string;
  /** Leaf first, then each issuer the TLS library could attach. */
  chain: ProbedCert[];
  /** Node's own verdict: chain to a trusted root, validity period and host name all fine. */
  authorized: boolean;
  authorizationError: string;
  /** RFC 6125 host name check of the leaf against the host that was asked for. */
  hostMatches: boolean;
}

export interface TlsFailure { ok: false; error: string }

const CURVE_BITS: Record<string, number> = { prime256v1: 256, secp384r1: 384, secp521r1: 521 };

function describe(cert: tls.DetailedPeerCertificate | tls.PeerCertificate): ProbedCert {
  const x509 = new X509Certificate(cert.raw);
  const key = x509.publicKey;
  const details = key.asymmetricKeyDetails ?? {};
  const keyType = key.asymmetricKeyType === 'rsa' ? 'RSA' : key.asymmetricKeyType === 'ec' ? 'EC' : String(key.asymmetricKeyType ?? '');
  const keyBits = keyType === 'RSA' ? Number(details.modulusLength) : CURVE_BITS[String(details.namedCurve)] ?? Number(cert.bits);
  const one = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value ?? '');
  return {
    subject: one(cert.subject?.CN),
    subjectOrg: one(cert.subject?.O),
    issuer: one(cert.issuer?.CN),
    issuerOrg: one(cert.issuer?.O),
    selfIssued: x509.subject === x509.issuer,
    validFromMs: parseCertTime(cert.valid_from),
    validToMs: parseCertTime(cert.valid_to),
    keyType,
    keyBits,
  };
}

/** Connects to `host:port`, accepts any certificate, and reports what was presented. */
export function probeTls(host: string, port = 443, timeoutMs = 12_000): Promise<TlsFacts | TlsFailure> {
  return new Promise(resolve => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        if (!cert || !cert.raw) { socket.destroy(); resolve({ ok: false, error: 'no certificate presented' }); return; }
        const chain: ProbedCert[] = [];
        const seen = new Set<string>();
        for (let current: tls.DetailedPeerCertificate | undefined = cert; current && current.raw && !seen.has(current.fingerprint256); current = current.issuerCertificate) {
          seen.add(current.fingerprint256);
          chain.push(describe(current));
        }
        const facts: TlsFacts = {
          ok: true,
          leaf: chain[0],
          sans: (cert.subjectaltname ?? '').split(', ').filter(Boolean).map(entry => (entry.startsWith('DNS:') ? entry.slice(4) : entry)),
          serial: cert.serialNumber,
          fingerprint256: cert.fingerprint256,
          protocol: (socket.getProtocol() ?? '').replace(/^TLSv/, 'TLS '),
          chain,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : '',
          hostMatches: tls.checkServerIdentity(host, cert) === undefined,
        };
        socket.end();
        resolve(facts);
      } catch (error) {
        socket.destroy();
        resolve({ ok: false, error: `could not read the certificate: ${(error as Error).message}` });
      }
    });
    socket.setTimeout(timeoutMs, () => { socket.destroy(); resolve({ ok: false, error: `no TLS handshake within ${timeoutMs} ms` }); });
    socket.on('error', error => resolve({ ok: false, error: error.message }));
  });
}

/** A records of `host` as the test machine's resolver sees them. */
export async function resolveA(host: string): Promise<string[]> {
  try { return await new Resolver().resolve4(host); } catch { return []; }
}

/** Whether `https://host/` answers with a Strict-Transport-Security header; null when it cannot be asked. */
export async function sendsHsts(host: string): Promise<boolean | null> {
  try {
    const response = await fetch(`https://${host}`, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(10_000), headers: { 'User-Agent': 'Mozilla/5.0 e2e-ssl-suite' } });
    return response.headers.has('strict-transport-security');
  } catch {
    return null;
  }
}
