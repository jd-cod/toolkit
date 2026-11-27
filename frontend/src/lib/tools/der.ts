/**
 * Minimal DER (ASN.1) reader for the certificate decoder.
 *
 * Written by hand instead of pulling in an X.509 library: the decoder runs in
 * the browser, handles private keys, and this keeps the code that touches
 * them small enough to read. It only reads; it never encodes.
 *
 * Input is untrusted, so every length is bounds-checked and nesting is capped.
 */

export interface DerNode {
  /** 0 universal, 1 application, 2 context-specific, 3 private. */
  cls: number;
  constructed: boolean;
  tag: number;
  /** Offset of the first byte of the element (its tag) in `source`. */
  start: number;
  /** Offset of the first content byte. */
  contentStart: number;
  /** Offset just past the last content byte. */
  end: number;
  source: Uint8Array;
  children: DerNode[];
}

export const TAG = {
  BOOLEAN: 1, INTEGER: 2, BIT_STRING: 3, OCTET_STRING: 4, NULL: 5, OID: 6, UTF8: 12,
  SEQUENCE: 16, SET: 17, PRINTABLE: 19, T61: 20, IA5: 22, UTC_TIME: 23, GENERALIZED_TIME: 24,
  UNIVERSAL: 28, BMP: 30,
};

const MAX_DEPTH = 32;
const MAX_NODES = 20000;

export class DerError extends Error {}

function readElement(source: Uint8Array, offset: number, limit: number, depth: number, budget: { nodes: number }): DerNode {
  if (depth > MAX_DEPTH) throw new DerError('Structure is nested too deeply.');
  if (++budget.nodes > MAX_NODES) throw new DerError('Structure is too large.');
  if (offset + 2 > limit) throw new DerError('Unexpected end of data.');

  const first = source[offset];
  const cls = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let cursor = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    let more = true;
    while (more) {
      if (cursor >= limit) throw new DerError('Unexpected end of data.');
      const byte = source[cursor++];
      tag = tag * 128 + (byte & 0x7f);
      more = (byte & 0x80) !== 0;
      if (tag > 0xffffff) throw new DerError('Unsupported tag.');
    }
  }

  if (cursor >= limit) throw new DerError('Unexpected end of data.');
  let length = source[cursor++];
  if (length === 0x80) throw new DerError('Indefinite lengths are not valid DER.');
  if (length > 0x80) {
    const count = length & 0x7f;
    if (count > 4 || cursor + count > limit) throw new DerError('Invalid length.');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + source[cursor++];
  }
  const end = cursor + length;
  if (end > limit) throw new DerError('Element is longer than the data.');

  const node: DerNode = { cls, constructed, tag, start: offset, contentStart: cursor, end, source, children: [] };
  if (constructed) {
    let child = cursor;
    while (child < end) {
      const element = readElement(source, child, end, depth + 1, budget);
      node.children.push(element);
      child = element.end;
    }
  }
  return node;
}

/** Parses one DER element starting at `offset`. Throws DerError on malformed input. */
export function parseDer(source: Uint8Array, offset = 0): DerNode {
  return readElement(source, offset, source.length, 0, { nodes: 0 });
}

/** Content bytes (without tag and length). */
export function contentOf(node: DerNode): Uint8Array {
  return node.source.subarray(node.contentStart, node.end);
}

/** The whole element, tag and length included. */
export function rawOf(node: DerNode): Uint8Array {
  return node.source.subarray(node.start, node.end);
}

export function isUniversal(node: DerNode | undefined, tag: number): node is DerNode {
  return Boolean(node) && node!.cls === 0 && node!.tag === tag;
}

export function isContext(node: DerNode | undefined, tag: number): node is DerNode {
  return Boolean(node) && node!.cls === 2 && node!.tag === tag;
}

export function toHex(bytes: Uint8Array, separator = ''): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += (i && separator ? separator : '') + bytes[i].toString(16).padStart(2, '0');
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function oidOf(node: DerNode): string {
  const bytes = contentOf(node);
  if (bytes.length === 0) throw new DerError('Empty object identifier.');
  const parts: number[] = [];
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = value * 128 + (bytes[i] & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER) throw new DerError('Object identifier is too large.');
    if ((bytes[i] & 0x80) === 0) {
      if (parts.length === 0) {
        const first = value < 40 ? 0 : value < 80 ? 1 : 2;
        parts.push(first, value - first * 40);
      } else {
        parts.push(value);
      }
      value = 0;
    }
  }
  return parts.join('.');
}

/** Integer content with the sign-padding zero removed. */
export function unsignedIntegerBytes(node: DerNode): Uint8Array {
  const bytes = contentOf(node);
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  return bytes.subarray(start);
}

export function bitLength(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  return (bytes.length - 1) * 8 + (32 - Math.clz32(bytes[0]));
}

/** Small non-negative integers only (versions, path lengths). Returns NaN when out of range. */
export function smallInteger(node: DerNode): number {
  const bytes = contentOf(node);
  if (bytes.length === 0 || bytes.length > 4 || (bytes[0] & 0x80)) return NaN;
  let value = 0;
  for (const byte of bytes) value = value * 256 + byte;
  return value;
}

/** BIT STRING payload without the leading unused-bits byte. */
export function bitStringBytes(node: DerNode): Uint8Array {
  const bytes = contentOf(node);
  return bytes.length > 0 ? bytes.subarray(1) : bytes;
}

export function stringOf(node: DerNode): string {
  const bytes = contentOf(node);
  if (node.cls === 0 && node.tag === TAG.BMP) {
    let out = '';
    for (let i = 0; i + 1 < bytes.length; i += 2) out += String.fromCharCode(bytes[i] * 256 + bytes[i + 1]);
    return out;
  }
  if (node.cls === 0 && node.tag === TAG.UNIVERSAL) {
    let out = '';
    for (let i = 0; i + 3 < bytes.length; i += 4) {
      const code = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
      out += code <= 0x10ffff ? String.fromCodePoint(code) : '\ufffd';
    }
    return out;
  }
  if (node.cls === 0 && node.tag === TAG.T61) {
    let out = '';
    for (const byte of bytes) out += String.fromCharCode(byte);
    return out;
  }
  return new TextDecoder('utf-8').decode(bytes);
}

/** UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ). Returns null when unreadable. */
export function timeOf(node: DerNode): Date | null {
  const text = stringOf(node);
  const utc = node.tag === TAG.UTC_TIME;
  const match = utc
    ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(text)
    : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/.exec(text);
  if (!match) return null;
  let year = Number(match[1]);
  // RFC 5280: two-digit years 50 to 99 are 19xx, 00 to 49 are 20xx.
  if (utc) year += year >= 50 ? 1900 : 2000;
  const date = new Date(Date.UTC(year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6] || 0)));
  return Number.isNaN(date.getTime()) ? null : date;
}
