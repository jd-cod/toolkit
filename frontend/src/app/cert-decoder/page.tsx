'use client';

import { useRef, useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { ToolEmptyState } from '@/components/ToolWorkspace';
import { Badge, CodeBlock, ErrorBanner, Field, FindingList, KeyValueTable, Panel, TextArea, TextInput, type Finding } from '@/components/ToolUi';
import {
  bytesToBase64, certificateFindings, chainFindings, decodePemText, fingerprint, matchesHostname, resolvePublicKey,
  type CertificateInfo, type CsrInfo, type DecodedBlock, type PrivateKeyInfo, type PublicKeyInfo,
} from '@/lib/tools/cert-decoder';

const SAMPLE = `-----BEGIN CERTIFICATE-----
MIIB5TCCAYygAwIBAgIUe6WnEqqr8hq1jUx6rc3zOMMy2OkwCgYIKoZIzj0EAwIw
PTELMAkGA1UEBhMCVVMxFDASBgNVBAoMC0V4YW1wbGUgSW5jMRgwFgYDVQQDDA93
d3cuZXhhbXBsZS5jb20wHhcNMjYxMTI3MTA0NTU5WhcNMjcxMTI3MTA0NTU5WjA9
MQswCQYDVQQGEwJVUzEUMBIGA1UECgwLRXhhbXBsZSBJbmMxGDAWBgNVBAMMD3d3
dy5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD+VpbaJJSCm
qCam0O1h1xpuju9l7H2udbTclF1ejq1senjkbx311jrO0Xj29gVPcVF3INs06Xjo
QLBBbXG2GYyjajBoMB0GA1UdDgQWBBQj1ebWt1TbGsLXsQlgr/mDW2nO1jAnBgNV
HREEIDAegg93d3cuZXhhbXBsZS5jb22CC2V4YW1wbGUuY29tMAkGA1UdEwQCMAAw
EwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDRwAwRAIgWBiY5/Ep2Pzq
w0uy6fqqXCHctY0p0m+2zGIhZzmep0ECIBLwSwWJalBzcJwM8ELZ6gKNyy61zqYD
uhWyO7x6GkX8
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE REQUEST-----
MIIBMzCB2QIBADA9MQswCQYDVQQGEwJVUzEUMBIGA1UECgwLRXhhbXBsZSBJbmMx
GDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABD+VpbaJJSCmqCam0O1h1xpuju9l7H2udbTclF1ejq1senjkbx311jrO0Xj2
9gVPcVF3INs06XjoQLBBbXG2GYygOjA4BgkqhkiG9w0BCQ4xKzApMCcGA1UdEQQg
MB6CD3d3dy5leGFtcGxlLmNvbYILZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSQAw
RgIhAMXKAYIE4/sTnLRN/OXVIK6jJok+pD2SZ7KqrpUk3Ql6AiEAooOb0uJmEEUd
TaydpZjhX3Wm6rLpY6R0ok5gumUFCMc=
-----END CERTIFICATE REQUEST-----
`;

const MAX_FILE_BYTES = 2 * 1024 * 1024;

const COMMANDS = `# Show a certificate
openssl x509 -in cert.pem -noout -text

# Show a certificate request
openssl req -in request.csr -noout -text -verify

# Convert DER (.cer, .der) to PEM, and back
openssl x509 -inform der -in cert.cer -out cert.pem
openssl x509 -outform der -in cert.pem -out cert.der

# Build a PFX / PKCS#12 file for Windows or IIS
openssl pkcs12 -export -out cert.pfx -inkey private.key -in cert.pem -certfile chain.pem

# Extract certificate and key from a PFX file
openssl pkcs12 -in cert.pfx -out cert-and-key.pem -noenc   # -nodes on OpenSSL 1.x

# Remove the passphrase from a key (work on a copy)
openssl pkey -in encrypted.key -out decrypted.key`;

interface Decoded {
  blocks: DecodedBlock[];
  fingerprints: Map<CertificateInfo, { sha256: string; sha1: string }>;
  decodedAt: Date;
}

const formatDate = (date: Date | null) => (date ? `${date.toISOString().replace('T', ' ').slice(0, 19)} UTC` : 'Unreadable');

function keyLabel(block: CsrInfo | PrivateKeyInfo | { kind: 'public-key'; publicKey: PublicKeyInfo }) {
  return block.kind === 'csr' ? 'Certificate request' : block.kind === 'private-key' ? 'Private key' : 'Public key';
}

function matchFindings(blocks: DecodedBlock[]): Finding[] {
  const certificate = blocks.find((block): block is CertificateInfo => block.kind === 'certificate');
  const others = blocks.filter((block): block is CsrInfo | PrivateKeyInfo | Extract<DecodedBlock, { kind: 'public-key' }> => block.kind === 'csr' || block.kind === 'private-key' || block.kind === 'public-key');
  const findings: Finding[] = [];

  if (certificate) {
    const name = certificate.subject.commonName || 'the first certificate';
    for (const other of others) {
      if (!other.publicKey.id || !certificate.publicKey.id) findings.push({ severity: 'info', title: `${keyLabel(other)} could not be compared`, detail: 'Its public key could not be worked out in this browser.' });
      else if (other.publicKey.id === certificate.publicKey.id) findings.push({ severity: 'ok', title: `${keyLabel(other)} matches the certificate for ${name}` });
      else findings.push({ severity: 'critical', title: `${keyLabel(other)} does not match the certificate for ${name}`, detail: 'They belong to different key pairs. A web server will refuse to start with this combination.' });
    }
  } else {
    const csr = others.find(block => block.kind === 'csr');
    const key = others.find(block => block.kind === 'private-key');
    if (csr && key) {
      if (!csr.publicKey.id || !key.publicKey.id) findings.push({ severity: 'info', title: 'Private key could not be compared with the request' });
      else if (csr.publicKey.id === key.publicKey.id) findings.push({ severity: 'ok', title: 'Private key matches the certificate request' });
      else findings.push({ severity: 'critical', title: 'Private key does not match the certificate request' });
    }
  }
  return findings;
}

function CertificatePanel({ cert, index, total, prints, now, host }: { cert: CertificateInfo; index: number; total: number; prints?: { sha256: string; sha1: string }; now: Date; host: string }) {
  const findings: Finding[] = certificateFindings(cert, now);
  if (host.trim() && index === 0) {
    findings.unshift(matchesHostname(cert, host)
      ? { severity: 'ok', title: `Covers ${host.trim()}` }
      : { severity: 'critical', title: `Does not cover ${host.trim()}`, detail: 'The host name is not among the certificate names.' });
  }
  const role = cert.isCa ? (cert.selfSigned ? 'Root CA' : 'Intermediate CA') : 'Server or client certificate';
  const names = [...cert.dnsNames, ...cert.ipAddresses, ...cert.emailAddresses, ...cert.uris];
  return (
    <Panel title={`${total > 1 ? `Certificate ${index + 1}: ` : 'Certificate: '}${cert.subject.commonName || cert.subject.text || 'unnamed'}`} icon="bi-file-earmark-lock" actions={<Badge tone="info">{role}</Badge>}>
      <FindingList findings={findings} />
      <div style={{ marginTop: '1rem' }}>
        <KeyValueTable rows={[
          ['Subject', cert.subject.text],
          ['Issuer', cert.issuer.text],
          ['Names (SAN)', names.join(', ')],
          ['Valid from', formatDate(cert.notBefore)],
          ['Valid until', formatDate(cert.notAfter)],
          ['Public key', cert.publicKey.description],
          ['Signature', cert.signatureAlgorithm],
          ['Serial number', cert.serialNumber],
          ['Validation', cert.validationType],
          ['Key usage', cert.keyUsage.join(', ')],
          ['Extended key usage', cert.extendedKeyUsage.join(', ')],
          ['Certificate authority', cert.isCa ? `Yes${cert.pathLength !== null ? `, path length ${cert.pathLength}` : ''}` : 'No'],
          ['Subject key ID', cert.subjectKeyId],
          ['Authority key ID', cert.authorityKeyId],
          ['OCSP', cert.ocspUrls.join(', ')],
          ['Issuer certificate', cert.caIssuerUrls.join(', ')],
          ['CRL', cert.crlUrls.join(', ')],
          ['Certificate transparency', cert.hasSctList ? 'Signed timestamps included' : ''],
          ['SHA-256 fingerprint', prints?.sha256 || ''],
          ['SHA-1 fingerprint', prints?.sha1 || ''],
        ].filter((row): row is [string, string] => row[1] !== '')} />
      </div>
    </Panel>
  );
}

function Results({ decoded, host }: { decoded: Decoded; host: string }) {
  const { blocks } = decoded;
  const certificates = blocks.filter((block): block is CertificateInfo => block.kind === 'certificate');
  const summary = [...matchFindings(blocks), ...chainFindings(certificates)];

  return (
    <>
      {summary.length > 0 && <Panel title="Key match and chain" icon="bi-link-45deg"><FindingList findings={summary} /></Panel>}

      {blocks.map((block, index) => {
        if (block.kind === 'certificate') {
          return <CertificatePanel key={index} cert={block} index={certificates.indexOf(block)} total={certificates.length} prints={decoded.fingerprints.get(block)} now={decoded.decodedAt} host={host} />;
        }
        if (block.kind === 'csr') {
          return (
            <Panel key={index} title={`Certificate request: ${block.subject.commonName || 'unnamed'}`} icon="bi-file-earmark-plus">
              <FindingList findings={[
                ...(block.publicKey.algorithm === 'RSA' && block.publicKey.bits < 2048 ? [{ severity: 'critical' as const, title: `Weak ${block.publicKey.bits}-bit RSA key`, detail: 'Certificate authorities require at least 2048 bits.' }] : []),
                ...(block.dnsNames.length === 0 && block.ipAddresses.length === 0 ? [{ severity: 'info' as const, title: 'No subject alternative names requested', detail: 'Most certificate authorities add the common name as a SAN for you, but list every host name you need.' }] : []),
                ...(block.weakSignature ? [{ severity: 'warning' as const, title: `Signed with ${block.signatureAlgorithm}` }] : []),
              ]} />
              <KeyValueTable rows={[
                ['Subject', block.subject.text],
                ['Requested names (SAN)', [...block.dnsNames, ...block.ipAddresses, ...block.emailAddresses].join(', ')],
                ['Public key', block.publicKey.description],
                ['Signature', block.signatureAlgorithm],
                ['Challenge password', block.hasChallengePassword ? 'Present' : ''],
              ]} />
            </Panel>
          );
        }
        if (block.kind === 'private-key') {
          return (
            <Panel key={index} title="Private key" icon="bi-key">
              <KeyValueTable rows={[['Format', block.format], ['Algorithm', block.publicKey.description]]} />
              <p className="tk-note" style={{ margin: '1rem 0 0' }}>The key was read in this browser only to compare it. It is not shown, stored or sent anywhere.</p>
            </Panel>
          );
        }
        if (block.kind === 'public-key') {
          return <Panel key={index} title="Public key" icon="bi-unlock"><KeyValueTable rows={[['Algorithm', block.publicKey.description]]} /></Panel>;
        }
        return <ErrorBanner key={index}>{block.label}: {block.reason}</ErrorBanner>;
      })}
    </>
  );
}

export default function CertDecoderPage() {
  const [text, setText] = useState('');
  const [host, setHost] = useState('');
  const [decoded, setDecoded] = useState<Decoded | null>(null);
  const [message, setMessage] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  const run = useRef(0);

  const decode = async (input = text) => {
    const id = ++run.current;
    setMessage('');
    const blocks = await Promise.all(decodePemText(input).map(block => (block.kind === 'private-key' ? resolvePublicKey(block) : block)));
    const fingerprints = new Map<CertificateInfo, { sha256: string; sha1: string }>();
    for (const block of blocks) {
      if (block.kind === 'certificate') fingerprints.set(block, { sha256: await fingerprint(block.der, 'SHA-256'), sha1: await fingerprint(block.der, 'SHA-1') });
    }
    if (id !== run.current) return;
    if (blocks.length === 0) {
      setDecoded(null);
      setMessage(input.trim() ? 'No certificate, request or key was found. Paste PEM text that starts with -----BEGIN, or the base64 of a DER file.' : '');
      return;
    }
    setDecoded({ blocks, fingerprints, decodedAt: new Date() });
  };

  const openFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) { setMessage('That file is too large to be a certificate or key.'); return; }
    const bytes = new Uint8Array(await file.arrayBuffer());
    // Binary DER files (.cer, .der, .p7b) are shown as base64 so they can be read like PEM.
    const content = bytes[0] === 0x30 ? bytesToBase64(bytes).replace(/(.{64})/g, '$1\n') : new TextDecoder().decode(bytes);
    setText(content);
    void decode(content);
  };

  const clear = () => { run.current += 1; setText(''); setDecoded(null); setMessage(''); };

  return (
    <ToolPage tool="cert-decoder" title="Certificate & CSR Decoder" icon="bi-file-earmark-lock-fill" lead="Decode certificates and requests, and check that a private key belongs to a certificate. Nothing leaves your browser.">
      <Panel>
        <Field label="Certificate, chain, CSR or key (PEM)" hint="Paste several blocks together to check that a key, a request and a certificate belong together.">
          <TextArea value={text} onChange={event => setText(event.target.value)} placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'} />
        </Field>
        <div className="tk-form" style={{ marginTop: '1rem' }}>
          <Field label="Host name to check (optional)" grow>
            <TextInput mono value={host} onChange={event => setHost(event.target.value)} placeholder="www.example.com" />
          </Field>
          <button type="button" className="btn-primary tk-submit" onClick={() => void decode()} disabled={!text.trim()}>Decode</button>
          <button type="button" className="btn-secondary tk-submit" onClick={() => fileInput.current?.click()}>Open file</button>
          <button type="button" className="btn-secondary tk-submit" onClick={() => { setText(SAMPLE); void decode(SAMPLE); }}>Load sample</button>
          <button type="button" className="btn-secondary tk-submit" onClick={clear} disabled={!text && !decoded}>Clear</button>
          <input ref={fileInput} type="file" hidden accept=".pem,.crt,.cer,.der,.csr,.key,.p7b,.p7c,.txt" aria-label="Open a certificate file" onChange={event => { void openFile(event.target.files?.[0]); event.target.value = ''; }} />
        </div>
      </Panel>

      {message && <ErrorBanner>{message}</ErrorBanner>}
      {!decoded && !message && <ToolEmptyState title="Decode a certificate">Paste a certificate, a chain, a certificate request or a private key. Everything is decoded in your browser, and private keys are never uploaded.</ToolEmptyState>}
      {decoded && <Results decoded={decoded} host={host} />}

      <Panel title="OpenSSL commands" icon="bi-terminal">
        <p className="tk-note">PFX files and passphrase-protected keys are not opened here. Convert them on your own machine:</p>
        <CodeBlock label="openssl" code={COMMANDS} />
      </Panel>
    </ToolPage>
  );
}
