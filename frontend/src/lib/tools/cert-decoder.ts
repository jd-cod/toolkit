import {
  DerError, TAG, bitLength, bitStringBytes, bytesEqual, contentOf, isContext, isUniversal, oidOf, parseDer, rawOf,
  smallInteger, stringOf, timeOf, toHex, unsignedIntegerBytes, type DerNode,
} from './der.ts';

/**
 * Decodes X.509 certificates, certificate requests (CSR) and keys, and checks
 * whether a key belongs to a certificate. Runs entirely in the browser: the
 * page that uses this never sends its input anywhere.
 */

const NAME_OIDS: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
  '2.5.4.5': 'serialNumber', '2.5.4.9': 'street', '2.5.4.17': 'postalCode', '2.5.4.15': 'businessCategory',
  '2.5.4.4': 'SN', '2.5.4.42': 'GN', '2.5.4.12': 'title', '2.5.4.97': 'organizationIdentifier',
  '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC', '0.9.2342.19200300.100.1.1': 'UID',
  '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionL', '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionST', '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC',
};

const SIGNATURE_OIDS: Record<string, { name: string; weak?: boolean }> = {
  '1.2.840.113549.1.1.4': { name: 'MD5 with RSA', weak: true },
  '1.2.840.113549.1.1.5': { name: 'SHA-1 with RSA', weak: true },
  '1.2.840.113549.1.1.11': { name: 'SHA-256 with RSA' },
  '1.2.840.113549.1.1.12': { name: 'SHA-384 with RSA' },
  '1.2.840.113549.1.1.13': { name: 'SHA-512 with RSA' },
  '1.2.840.113549.1.1.10': { name: 'RSASSA-PSS' },
  '1.2.840.10045.4.1': { name: 'ECDSA with SHA-1', weak: true },
  '1.2.840.10045.4.3.2': { name: 'ECDSA with SHA-256' },
  '1.2.840.10045.4.3.3': { name: 'ECDSA with SHA-384' },
  '1.2.840.10045.4.3.4': { name: 'ECDSA with SHA-512' },
  '1.3.101.112': { name: 'Ed25519' },
  '1.3.101.113': { name: 'Ed448' },
};

const OID_RSA = '1.2.840.113549.1.1.1';
const OID_EC = '1.2.840.10045.2.1';
const OID_ED25519 = '1.3.101.112';
const OID_ED448 = '1.3.101.113';
const OID_DSA = '1.2.840.10040.4.1';

const CURVES: Record<string, { name: string; bits: number; webCrypto?: string }> = {
  '1.2.840.10045.3.1.7': { name: 'P-256', bits: 256, webCrypto: 'P-256' },
  '1.3.132.0.34': { name: 'P-384', bits: 384, webCrypto: 'P-384' },
  '1.3.132.0.35': { name: 'P-521', bits: 521, webCrypto: 'P-521' },
  '1.3.132.0.10': { name: 'secp256k1', bits: 256 },
};

const EKU_OIDS: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'TLS server', '1.3.6.1.5.5.7.3.2': 'TLS client', '1.3.6.1.5.5.7.3.3': 'Code signing',
  '1.3.6.1.5.5.7.3.4': 'Email protection', '1.3.6.1.5.5.7.3.8': 'Time stamping', '1.3.6.1.5.5.7.3.9': 'OCSP signing',
  '2.5.29.37.0': 'Any purpose',
};

const POLICY_OIDS: Record<string, string> = {
  '2.23.140.1.2.1': 'Domain validated (DV)', '2.23.140.1.2.2': 'Organization validated (OV)',
  '2.23.140.1.2.3': 'Individual validated (IV)', '2.23.140.1.1': 'Extended validation (EV)',
};

const KEY_USAGE_BITS = ['Digital signature', 'Non-repudiation', 'Key encipherment', 'Data encipherment', 'Key agreement', 'Certificate signing', 'CRL signing', 'Encipher only', 'Decipher only'];

export interface NameInfo {
  /** Ordered attributes as they appear, e.g. [['C','US'], ['O','Example'], ['CN','example.com']]. */
  attributes: Array<[string, string]>;
  /** One-line form, most specific first: CN=example.com, O=Example, C=US. */
  text: string;
  commonName: string;
  organization: string;
}

/**
 * Identifies a public key independent of how it is wrapped, so the key in a
 * certificate, a CSR and a private key file can be compared.
 */
export interface PublicKeyInfo {
  algorithm: 'RSA' | 'EC' | 'Ed25519' | 'Ed448' | 'DSA' | 'Unknown';
  bits: number;
  curve: string;
  /** Comparable identity, or '' when it cannot be determined. */
  id: string;
  description: string;
}

export interface CertificateInfo {
  kind: 'certificate';
  version: number;
  serialNumber: string;
  subject: NameInfo;
  issuer: NameInfo;
  notBefore: Date | null;
  notAfter: Date | null;
  signatureAlgorithm: string;
  weakSignature: boolean;
  publicKey: PublicKeyInfo;
  selfSigned: boolean;
  isCa: boolean;
  pathLength: number | null;
  dnsNames: string[];
  ipAddresses: string[];
  emailAddresses: string[];
  uris: string[];
  keyUsage: string[];
  extendedKeyUsage: string[];
  validationType: string;
  subjectKeyId: string;
  authorityKeyId: string;
  ocspUrls: string[];
  caIssuerUrls: string[];
  crlUrls: string[];
  hasSctList: boolean;
  subjectRaw: Uint8Array;
  issuerRaw: Uint8Array;
  der: Uint8Array;
}

export interface CsrInfo {
  kind: 'csr';
  subject: NameInfo;
  signatureAlgorithm: string;
  weakSignature: boolean;
  publicKey: PublicKeyInfo;
  dnsNames: string[];
  ipAddresses: string[];
  emailAddresses: string[];
  hasChallengePassword: boolean;
  der: Uint8Array;
}

export interface PrivateKeyInfo {
  kind: 'private-key';
  format: 'PKCS#8' | 'PKCS#1 (RSA)' | 'SEC1 (EC)';
  publicKey: PublicKeyInfo;
  /** Set when the public half is not stored in the file and has to be derived with WebCrypto. */
  derive: { pkcs8: Uint8Array; algorithm: 'EC' | 'Ed25519'; curveOid: string } | null;
}

export interface PublicKeyBlock {
  kind: 'public-key';
  publicKey: PublicKeyInfo;
}

export interface UnreadableBlock {
  kind: 'unreadable';
  label: string;
  reason: string;
}

export type DecodedBlock = CertificateInfo | CsrInfo | PrivateKeyInfo | PublicKeyBlock | UnreadableBlock;

export interface PemBlock {
  label: string;
  der: Uint8Array;
  encrypted: boolean;
}

// ─── PEM ─────────────────────────────────────────────────

function base64ToBytes(text: string): Uint8Array | null {
  const clean = text.replace(/[\s]+/g, '');
  if (!clean || !/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) return null;
  try {
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export function toPem(label: string, der: Uint8Array): string {
  const body = bytesToBase64(der).replace(/(.{64})/g, '$1\n').trimEnd();
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

/**
 * Finds every PEM block in `text`. When there is no PEM armor at all, the
 * text is tried as bare base64 DER and returned as one block with an empty
 * label.
 */
export function parsePemBlocks(text: string): PemBlock[] {
  const blocks: PemBlock[] = [];
  const pattern = /-----BEGIN ([A-Z0-9 #]+)-----([\s\S]*?)-----END \1-----/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null && blocks.length < 50) {
    const lines = match[2].split(/\r?\n/);
    // Legacy encrypted keys carry RFC 1421 headers (Proc-Type, DEK-Info) before the base64.
    const headerLines = lines.filter(line => /^[A-Za-z-]+:\s/.test(line));
    const body = lines.filter(line => !/^[A-Za-z-]+:\s/.test(line)).join('');
    const der = base64ToBytes(body);
    const encrypted = match[1].includes('ENCRYPTED') || headerLines.some(line => /ENCRYPTED/.test(line));
    blocks.push({ label: match[1].trim(), der: der || new Uint8Array(0), encrypted });
  }
  if (blocks.length === 0 && !text.includes('-----BEGIN')) {
    const der = base64ToBytes(text);
    if (der && der.length > 16 && der[0] === 0x30) blocks.push({ label: '', der, encrypted: false });
  }
  return blocks;
}

// ─── Shared pieces ───────────────────────────────────────

function expect(condition: unknown, message: string): asserts condition {
  if (!condition) throw new DerError(message);
}

function decodeName(node: DerNode): NameInfo {
  expect(isUniversal(node, TAG.SEQUENCE), 'Name is not a sequence.');
  const attributes: Array<[string, string]> = [];
  for (const rdn of node.children) {
    for (const attribute of rdn.children) {
      const [type, value] = attribute.children;
      if (!isUniversal(type, TAG.OID) || !value) continue;
      const oid = oidOf(type);
      attributes.push([NAME_OIDS[oid] || oid, stringOf(value)]);
    }
  }
  const escape = (value: string) => value.replace(/([,+"\\<>;])/g, '\\$1');
  return {
    attributes,
    text: [...attributes].reverse().map(([key, value]) => `${key}=${escape(value)}`).join(', '),
    commonName: attributes.find(([key]) => key === 'CN')?.[1] || '',
    organization: attributes.find(([key]) => key === 'O')?.[1] || '',
  };
}

function rsaIdentity(modulus: Uint8Array, exponent: Uint8Array): PublicKeyInfo {
  const bits = bitLength(modulus);
  return { algorithm: 'RSA', bits, curve: '', id: `rsa:${toHex(modulus)}:${toHex(exponent)}`, description: `RSA ${bits} bit` };
}

function ecIdentity(curveOid: string, point: Uint8Array | null): PublicKeyInfo {
  const curve = CURVES[curveOid];
  const name = curve?.name || curveOid || 'unknown curve';
  return { algorithm: 'EC', bits: curve?.bits || 0, curve: name, id: point ? `ec:${curveOid}:${toHex(point)}` : '', description: `EC ${name}` };
}

function decodeSpki(node: DerNode): PublicKeyInfo {
  expect(isUniversal(node, TAG.SEQUENCE) && node.children.length >= 2, 'Public key info is malformed.');
  const [algorithm, keyBits] = node.children;
  expect(isUniversal(algorithm.children[0], TAG.OID) && isUniversal(keyBits, TAG.BIT_STRING), 'Public key info is malformed.');
  const oid = oidOf(algorithm.children[0]);
  const key = bitStringBytes(keyBits);

  if (oid === OID_RSA) {
    const rsa = parseDer(key);
    expect(rsa.children.length >= 2, 'RSA public key is malformed.');
    return rsaIdentity(unsignedIntegerBytes(rsa.children[0]), unsignedIntegerBytes(rsa.children[1]));
  }
  if (oid === OID_EC) {
    const params = algorithm.children[1];
    return ecIdentity(isUniversal(params, TAG.OID) ? oidOf(params) : '', key);
  }
  if (oid === OID_ED25519) return { algorithm: 'Ed25519', bits: 256, curve: '', id: `ed25519:${toHex(key)}`, description: 'Ed25519' };
  if (oid === OID_ED448) return { algorithm: 'Ed448', bits: 456, curve: '', id: `ed448:${toHex(key)}`, description: 'Ed448' };
  if (oid === OID_DSA) return { algorithm: 'DSA', bits: 0, curve: '', id: `dsa:${toHex(key)}`, description: 'DSA' };
  return { algorithm: 'Unknown', bits: 0, curve: '', id: `raw:${oid}:${toHex(key)}`, description: `Unknown algorithm (${oid})` };
}

function signatureName(node: DerNode): { name: string; weak: boolean } {
  const oid = isUniversal(node.children[0], TAG.OID) ? oidOf(node.children[0]) : '';
  const known = SIGNATURE_OIDS[oid];
  return { name: known?.name || oid || 'Unknown', weak: Boolean(known?.weak) };
}

function formatIp(bytes: Uint8Array): string {
  if (bytes.length === 4) return Array.from(bytes).join('.');
  if (bytes.length !== 16) return toHex(bytes);
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  // Collapse the longest run of zero groups, as in RFC 5952.
  let best = { start: -1, length: 0 };
  for (let i = 0; i < 8; i++) {
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > best.length) best = { start: i, length: j - i };
    if (j > i) i = j - 1;
  }
  if (best.length < 2) return groups.join(':');
  return `${groups.slice(0, best.start).join(':')}::${groups.slice(best.start + best.length).join(':')}`;
}

interface AltNames { dns: string[]; ips: string[]; emails: string[]; uris: string[] }

function decodeGeneralNames(node: DerNode): AltNames {
  const names: AltNames = { dns: [], ips: [], emails: [], uris: [] };
  for (const name of node.children) {
    if (name.cls !== 2) continue;
    if (name.tag === 2) names.dns.push(stringOf(name));
    else if (name.tag === 1) names.emails.push(stringOf(name));
    else if (name.tag === 6) names.uris.push(stringOf(name));
    else if (name.tag === 7) names.ips.push(formatIp(contentOf(name)));
  }
  return names;
}

interface Extensions {
  altNames: AltNames;
  isCa: boolean;
  pathLength: number | null;
  keyUsage: string[];
  extendedKeyUsage: string[];
  validationType: string;
  subjectKeyId: string;
  authorityKeyId: string;
  ocspUrls: string[];
  caIssuerUrls: string[];
  crlUrls: string[];
  hasSctList: boolean;
}

function decodeExtensions(list: DerNode | undefined): Extensions {
  const out: Extensions = {
    altNames: { dns: [], ips: [], emails: [], uris: [] }, isCa: false, pathLength: null, keyUsage: [], extendedKeyUsage: [],
    validationType: '', subjectKeyId: '', authorityKeyId: '', ocspUrls: [], caIssuerUrls: [], crlUrls: [], hasSctList: false,
  };
  if (!list) return out;

  for (const extension of list.children) {
    const idNode = extension.children[0];
    const valueNode = extension.children[extension.children.length - 1];
    if (!isUniversal(idNode, TAG.OID) || !isUniversal(valueNode, TAG.OCTET_STRING)) continue;
    const oid = oidOf(idNode);
    let value: DerNode;
    try {
      value = parseDer(contentOf(valueNode));
    } catch {
      continue;
    }

    if (oid === '2.5.29.17') {
      out.altNames = decodeGeneralNames(value);
    } else if (oid === '2.5.29.19') {
      const [first, second] = value.children;
      out.isCa = isUniversal(first, TAG.BOOLEAN) && contentOf(first)[0] !== 0;
      const length = isUniversal(first, TAG.INTEGER) ? first : isUniversal(second, TAG.INTEGER) ? second : undefined;
      if (length) out.pathLength = smallInteger(length);
    } else if (oid === '2.5.29.15') {
      const bits = bitStringBytes(value);
      KEY_USAGE_BITS.forEach((name, index) => {
        const byte = bits[index >> 3];
        if (byte !== undefined && (byte & (0x80 >> (index & 7)))) out.keyUsage.push(name);
      });
    } else if (oid === '2.5.29.37') {
      out.extendedKeyUsage = value.children.filter(child => isUniversal(child, TAG.OID)).map(child => { const id = oidOf(child); return EKU_OIDS[id] || id; });
    } else if (oid === '2.5.29.14') {
      out.subjectKeyId = toHex(contentOf(value), ':');
    } else if (oid === '2.5.29.35') {
      const keyId = value.children.find(child => isContext(child, 0));
      if (keyId) out.authorityKeyId = toHex(contentOf(keyId), ':');
    } else if (oid === '1.3.6.1.5.5.7.1.1') {
      for (const access of value.children) {
        const [method, location] = access.children;
        if (!isUniversal(method, TAG.OID) || !isContext(location, 6)) continue;
        const id = oidOf(method);
        if (id === '1.3.6.1.5.5.7.48.1') out.ocspUrls.push(stringOf(location));
        else if (id === '1.3.6.1.5.5.7.48.2') out.caIssuerUrls.push(stringOf(location));
      }
    } else if (oid === '2.5.29.31') {
      const collect = (node: DerNode) => {
        if (isContext(node, 6) && !node.constructed) out.crlUrls.push(stringOf(node));
        node.children.forEach(collect);
      };
      collect(value);
    } else if (oid === '2.5.29.32') {
      for (const policy of value.children) {
        const id = isUniversal(policy.children[0], TAG.OID) ? oidOf(policy.children[0]) : '';
        if (POLICY_OIDS[id]) out.validationType = POLICY_OIDS[id];
      }
    } else if (oid === '1.3.6.1.4.1.11129.2.4.2') {
      out.hasSctList = true;
    }
  }
  return out;
}

// ─── Certificates and CSRs ────────────────────────────────

export function decodeCertificate(der: Uint8Array): CertificateInfo {
  const root = parseDer(der);
  expect(isUniversal(root, TAG.SEQUENCE) && root.children.length === 3, 'Not an X.509 certificate.');
  const [tbs, signatureAlgorithm] = root.children;
  expect(isUniversal(tbs, TAG.SEQUENCE), 'Not an X.509 certificate.');

  const fields = [...tbs.children];
  let version = 1;
  if (isContext(fields[0], 0)) {
    const versionNode = fields.shift()!.children[0];
    version = (versionNode ? smallInteger(versionNode) : 0) + 1;
  }
  const [serial, , issuer, validity, subject, spki, ...rest] = fields;
  expect(isUniversal(serial, TAG.INTEGER) && issuer && validity && subject && spki, 'Not an X.509 certificate.');
  expect(validity.children.length === 2, 'Certificate validity is malformed.');

  const extensionWrapper = rest.find(node => isContext(node, 3));
  const extensions = decodeExtensions(extensionWrapper?.children[0]);
  const signature = signatureName(signatureAlgorithm);
  const subjectRaw = rawOf(subject);
  const issuerRaw = rawOf(issuer);

  return {
    kind: 'certificate',
    version,
    serialNumber: toHex(contentOf(serial), ':'),
    subject: decodeName(subject),
    issuer: decodeName(issuer),
    notBefore: timeOf(validity.children[0]),
    notAfter: timeOf(validity.children[1]),
    signatureAlgorithm: signature.name,
    weakSignature: signature.weak,
    publicKey: decodeSpki(spki),
    selfSigned: bytesEqual(subjectRaw, issuerRaw),
    isCa: extensions.isCa,
    pathLength: extensions.pathLength,
    dnsNames: extensions.altNames.dns,
    ipAddresses: extensions.altNames.ips,
    emailAddresses: extensions.altNames.emails,
    uris: extensions.altNames.uris,
    keyUsage: extensions.keyUsage,
    extendedKeyUsage: extensions.extendedKeyUsage,
    validationType: extensions.validationType,
    subjectKeyId: extensions.subjectKeyId,
    authorityKeyId: extensions.authorityKeyId,
    ocspUrls: extensions.ocspUrls,
    caIssuerUrls: extensions.caIssuerUrls,
    crlUrls: extensions.crlUrls,
    hasSctList: extensions.hasSctList,
    subjectRaw,
    issuerRaw,
    der,
  };
}

export function decodeCsr(der: Uint8Array): CsrInfo {
  const root = parseDer(der);
  expect(isUniversal(root, TAG.SEQUENCE) && root.children.length === 3, 'Not a certificate request.');
  const [info, signatureAlgorithm] = root.children;
  const [version, subject, spki, attributes] = info.children;
  expect(isUniversal(version, TAG.INTEGER) && isUniversal(subject, TAG.SEQUENCE) && isUniversal(spki, TAG.SEQUENCE), 'Not a certificate request.');

  let altNames: AltNames = { dns: [], ips: [], emails: [], uris: [] };
  let hasChallengePassword = false;
  if (isContext(attributes, 0)) {
    for (const attribute of attributes.children) {
      const [type, values] = attribute.children;
      if (!isUniversal(type, TAG.OID) || !values) continue;
      const oid = oidOf(type);
      if (oid === '1.2.840.113549.1.9.14' && values.children[0]) altNames = decodeExtensions(values.children[0]).altNames;
      else if (oid === '1.2.840.113549.1.9.7') hasChallengePassword = true;
    }
  }
  const signature = signatureName(signatureAlgorithm);
  return {
    kind: 'csr',
    subject: decodeName(subject),
    signatureAlgorithm: signature.name,
    weakSignature: signature.weak,
    publicKey: decodeSpki(spki),
    dnsNames: altNames.dns,
    ipAddresses: altNames.ips,
    emailAddresses: altNames.emails,
    hasChallengePassword,
    der,
  };
}

/** Certificates inside a PKCS#7 / .p7b bundle. */
export function certificatesFromPkcs7(der: Uint8Array): Uint8Array[] {
  const root = parseDer(der);
  const [contentType, wrapper] = root.children;
  expect(isUniversal(contentType, TAG.OID) && oidOf(contentType) === '1.2.840.113549.1.7.2' && isContext(wrapper, 0), 'Not a PKCS#7 certificate bundle.');
  const signedData = wrapper.children[0];
  const certificates = signedData?.children.find(node => isContext(node, 0));
  return certificates ? certificates.children.filter(node => isUniversal(node, TAG.SEQUENCE)).map(node => rawOf(node).slice()) : [];
}

// ─── Keys ────────────────────────────────────────────────

function decodeRsaPrivate(node: DerNode): PublicKeyInfo {
  expect(isUniversal(node, TAG.SEQUENCE) && node.children.length >= 3, 'RSA private key is malformed.');
  return rsaIdentity(unsignedIntegerBytes(node.children[1]), unsignedIntegerBytes(node.children[2]));
}

/** SEC1 ECPrivateKey: the public point is optional, the curve may come from the wrapper. */
function decodeEcPrivate(node: DerNode, outerCurve: string): { publicKey: PublicKeyInfo; curveOid: string } {
  expect(isUniversal(node, TAG.SEQUENCE) && node.children.length >= 2, 'EC private key is malformed.');
  const params = node.children.find(child => isContext(child, 0))?.children[0];
  const curveOid = outerCurve || (isUniversal(params, TAG.OID) ? oidOf(params) : '');
  const publicNode = node.children.find(child => isContext(child, 1))?.children[0];
  const point = isUniversal(publicNode, TAG.BIT_STRING) ? bitStringBytes(publicNode) : null;
  return { publicKey: ecIdentity(curveOid, point), curveOid };
}

/** Wraps a SEC1 EC key in PKCS#8 so WebCrypto can import it. */
function wrapSec1(sec1: Uint8Array, curveOid: string): Uint8Array {
  const encodeLength = (length: number) => (length < 0x80 ? [length] : length < 0x100 ? [0x81, length] : [0x82, length >> 8, length & 0xff]);
  const tlv = (tag: number, body: number[] | Uint8Array) => [tag, ...encodeLength(body.length), ...body];
  const oid = (dotted: string) => {
    const parts = dotted.split('.').map(Number);
    const body = [parts[0] * 40 + parts[1]];
    for (const part of parts.slice(2)) {
      const chunk = [part & 0x7f];
      for (let rest = Math.floor(part / 128); rest > 0; rest = Math.floor(rest / 128)) chunk.unshift((rest & 0x7f) | 0x80);
      body.push(...chunk);
    }
    return tlv(0x06, body);
  };
  const algorithm = tlv(0x30, [...oid(OID_EC), ...oid(curveOid)]);
  return new Uint8Array(tlv(0x30, [0x02, 0x01, 0x00, ...algorithm, ...tlv(0x04, sec1)]));
}

export function decodePrivateKey(label: string, der: Uint8Array): PrivateKeyInfo {
  const root = parseDer(der);
  expect(isUniversal(root, TAG.SEQUENCE), 'Not a private key.');

  if (label === 'RSA PRIVATE KEY') return { kind: 'private-key', format: 'PKCS#1 (RSA)', publicKey: decodeRsaPrivate(root), derive: null };
  if (label === 'EC PRIVATE KEY') {
    const { publicKey, curveOid } = decodeEcPrivate(root, '');
    const derive = !publicKey.id && CURVES[curveOid]?.webCrypto ? { pkcs8: wrapSec1(der, curveOid), algorithm: 'EC' as const, curveOid } : null;
    return { kind: 'private-key', format: 'SEC1 (EC)', publicKey, derive };
  }

  // PKCS#8 PrivateKeyInfo: version, algorithm, OCTET STRING with the key.
  const [, algorithm, keyOctets] = root.children;
  expect(isUniversal(algorithm, TAG.SEQUENCE) && isUniversal(algorithm.children[0], TAG.OID) && isUniversal(keyOctets, TAG.OCTET_STRING), 'Not a PKCS#8 private key.');
  const oid = oidOf(algorithm.children[0]);
  if (oid === OID_RSA) return { kind: 'private-key', format: 'PKCS#8', publicKey: decodeRsaPrivate(parseDer(contentOf(keyOctets))), derive: null };
  if (oid === OID_EC) {
    const outerCurve = isUniversal(algorithm.children[1], TAG.OID) ? oidOf(algorithm.children[1]) : '';
    const { publicKey, curveOid } = decodeEcPrivate(parseDer(contentOf(keyOctets)), outerCurve);
    const derive = !publicKey.id && CURVES[curveOid]?.webCrypto ? { pkcs8: der, algorithm: 'EC' as const, curveOid } : null;
    return { kind: 'private-key', format: 'PKCS#8', publicKey, derive };
  }
  if (oid === OID_ED25519) {
    return { kind: 'private-key', format: 'PKCS#8', publicKey: { algorithm: 'Ed25519', bits: 256, curve: '', id: '', description: 'Ed25519' }, derive: { pkcs8: der, algorithm: 'Ed25519', curveOid: '' } };
  }
  return { kind: 'private-key', format: 'PKCS#8', publicKey: { algorithm: 'Unknown', bits: 0, curve: '', id: '', description: `Unknown algorithm (${oid})` }, derive: null };
}

function base64UrlToBytes(value: string): Uint8Array {
  return base64ToBytes(value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=')) || new Uint8Array(0);
}

/**
 * Fills in the public identity of a key whose file stores only the private
 * half, by importing it with WebCrypto and exporting the public part. The key
 * stays in this process. Returns the key unchanged when WebCrypto cannot read it.
 */
export async function resolvePublicKey(key: PrivateKeyInfo): Promise<PrivateKeyInfo> {
  if (key.publicKey.id || !key.derive) return key;
  try {
    const { subtle } = globalThis.crypto;
    const data = key.derive.pkcs8.slice().buffer as ArrayBuffer;
    if (key.derive.algorithm === 'EC') {
      const namedCurve = CURVES[key.derive.curveOid]?.webCrypto;
      if (!namedCurve) return key;
      const imported = await subtle.importKey('pkcs8', data, { name: 'ECDSA', namedCurve }, true, ['sign']);
      const jwk = await subtle.exportKey('jwk', imported);
      const x = base64UrlToBytes(jwk.x || '');
      const y = base64UrlToBytes(jwk.y || '');
      const point = new Uint8Array(1 + x.length + y.length);
      point[0] = 4;
      point.set(x, 1);
      point.set(y, 1 + x.length);
      return { ...key, publicKey: ecIdentity(key.derive.curveOid, point), derive: null };
    }
    const imported = await subtle.importKey('pkcs8', data, { name: 'Ed25519' }, true, ['sign']);
    const jwk = await subtle.exportKey('jwk', imported);
    return { ...key, publicKey: { ...key.publicKey, id: `ed25519:${toHex(base64UrlToBytes(jwk.x || ''))}` }, derive: null };
  } catch {
    return key;
  }
}

// ─── Whole input ─────────────────────────────────────────

function unreadable(label: string, reason: string): UnreadableBlock {
  return { kind: 'unreadable', label: label || 'Data', reason };
}

function decodeBlock(block: PemBlock): DecodedBlock[] {
  const { label, der } = block;
  if (label === 'OPENSSH PRIVATE KEY') return [unreadable(label, 'OpenSSH private keys use their own format and are not decoded here. Convert a copy with: ssh-keygen -p -m PEM -f keyfile')];
  if (block.encrypted) return [unreadable(label, 'This key is encrypted with a passphrase and cannot be read. Decrypt a copy first: openssl pkey -in encrypted.key -out decrypted.key')];
  if (der.length === 0) return [unreadable(label, 'The block is not valid base64.')];

  try {
    if (label === 'CERTIFICATE' || label === 'TRUSTED CERTIFICATE' || label === 'X509 CERTIFICATE') return [decodeCertificate(der)];
    if (label === 'CERTIFICATE REQUEST' || label === 'NEW CERTIFICATE REQUEST') return [decodeCsr(der)];
    if (label === 'PRIVATE KEY' || label === 'RSA PRIVATE KEY' || label === 'EC PRIVATE KEY') return [decodePrivateKey(label, der)];
    if (label === 'PUBLIC KEY') return [{ kind: 'public-key', publicKey: decodeSpki(parseDer(der)) }];
    if (label === 'PKCS7' || label === 'CMS') {
      const certificates = certificatesFromPkcs7(der);
      return certificates.length ? certificates.map(decodeCertificate) : [unreadable(label, 'The bundle contains no certificates.')];
    }
    if (label === '') {
      // Bare base64: work out what it is from its shape.
      for (const attempt of [() => decodeCertificate(der), () => decodeCsr(der), () => decodePrivateKey('PRIVATE KEY', der)]) {
        try { return [attempt()]; } catch { /* try the next shape */ }
      }
      return [unreadable(label, 'The data is not a certificate, a certificate request or a private key.')];
    }
    return [unreadable(label, `"${label}" blocks are not supported.`)];
  } catch (err) {
    return [unreadable(label, err instanceof DerError ? err.message : 'The block could not be decoded.')];
  }
}

export function decodePemText(text: string): DecodedBlock[] {
  if (text.length > 2_000_000) return [unreadable('Input', 'The input is too large.')];
  return parsePemBlocks(text).flatMap(decodeBlock);
}

export interface CertFinding {
  severity: 'critical' | 'warning' | 'info' | 'ok';
  title: string;
  detail?: string;
}

const DAY_MS = 86400000;

export function daysUntil(date: Date | null, now: Date): number | null {
  return date ? Math.floor((date.getTime() - now.getTime()) / DAY_MS) : null;
}

export function certificateFindings(cert: CertificateInfo, now: Date): CertFinding[] {
  const findings: CertFinding[] = [];
  const days = daysUntil(cert.notAfter, now);
  const isLeaf = !cert.isCa;

  if (cert.notBefore && cert.notBefore.getTime() > now.getTime()) findings.push({ severity: 'critical', title: 'Certificate is not valid yet', detail: `It becomes valid on ${cert.notBefore.toISOString().slice(0, 10)}.` });
  if (days === null) findings.push({ severity: 'warning', title: 'Expiry date could not be read' });
  else if (days < 0) findings.push({ severity: 'critical', title: `Certificate expired ${-days} day${days === -1 ? '' : 's'} ago` });
  else if (days <= 30) findings.push({ severity: 'warning', title: `Certificate expires in ${days} day${days === 1 ? '' : 's'}`, detail: 'Renew it now.' });
  else findings.push({ severity: 'ok', title: `Valid for ${days} more days` });

  if (cert.publicKey.algorithm === 'RSA' && cert.publicKey.bits < 2048) findings.push({ severity: 'critical', title: `Weak ${cert.publicKey.bits}-bit RSA key`, detail: 'Browsers and certificate authorities require at least 2048 bits.' });
  if (cert.weakSignature && !cert.selfSigned) findings.push({ severity: 'critical', title: `Signed with ${cert.signatureAlgorithm}`, detail: 'MD5 and SHA-1 signatures are rejected by browsers.' });
  if (isLeaf && cert.dnsNames.length === 0 && cert.ipAddresses.length === 0) findings.push({ severity: 'warning', title: 'No subject alternative names', detail: 'Browsers ignore the common name and require the host name in the SAN extension.' });
  if (cert.selfSigned) findings.push({ severity: 'info', title: cert.isCa ? 'Self-signed root certificate' : 'Self-signed certificate', detail: cert.isCa ? '' : 'Clients will not trust it unless it is installed as trusted.' });
  if (isLeaf && cert.notBefore && cert.notAfter && (cert.notAfter.getTime() - cert.notBefore.getTime()) / DAY_MS > 398) {
    findings.push({ severity: 'info', title: 'Validity period is longer than 398 days', detail: 'Publicly trusted certificates are limited to 398 days or less. A longer period means a private CA or an old certificate.' });
  }
  return findings;
}

/** Does `host` match one of the certificate's names? Wildcards cover exactly one label. */
export function matchesHostname(cert: CertificateInfo, host: string): boolean {
  const wanted = host.trim().toLowerCase().replace(/\.$/, '');
  if (!wanted) return false;
  if (cert.ipAddresses.includes(wanted)) return true;
  const names = cert.dnsNames.length > 0 ? cert.dnsNames : cert.subject.commonName ? [cert.subject.commonName] : [];
  return names.some(name => {
    const pattern = name.toLowerCase().replace(/\.$/, '');
    if (pattern === wanted) return true;
    if (!pattern.startsWith('*.')) return false;
    const dot = wanted.indexOf('.');
    return dot > 0 && wanted.slice(dot + 1) === pattern.slice(2) && wanted.slice(dot + 1).includes('.');
  });
}

/** Checks that each certificate is followed by the certificate that issued it. */
export function chainFindings(certs: CertificateInfo[]): CertFinding[] {
  if (certs.length < 2) return [];
  const findings: CertFinding[] = [];
  let ordered = true;
  for (let i = 0; i < certs.length - 1; i++) {
    if (!bytesEqual(certs[i].issuerRaw, certs[i + 1].subjectRaw)) {
      ordered = false;
      const issuer = certs.find(candidate => candidate !== certs[i] && bytesEqual(candidate.subjectRaw, certs[i].issuerRaw));
      findings.push(issuer
        ? { severity: 'warning', title: `Certificate ${i + 1} is not followed by its issuer`, detail: `Its issuer is in the bundle but in a different position. Servers should send the chain in order: server certificate first, then each issuer.` }
        : { severity: 'critical', title: `The issuer of certificate ${i + 1} is missing`, detail: `Nothing in the bundle has the subject "${certs[i].issuer.text}". Clients that do not have this intermediate cached will fail to verify the chain.` });
    }
  }
  if (certs[0].isCa) findings.push({ severity: 'warning', title: 'The first certificate is a CA certificate', detail: 'The server certificate should come first.' });
  if (ordered) findings.push({ severity: 'ok', title: `Chain of ${certs.length} certificates is in the right order` });
  return findings;
}

/** SHA-256 or SHA-1 fingerprint as colon-separated hex. */
export async function fingerprint(der: Uint8Array, algorithm: 'SHA-256' | 'SHA-1'): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(algorithm, der.slice().buffer as ArrayBuffer);
  return toHex(new Uint8Array(digest), ':').toUpperCase();
}
