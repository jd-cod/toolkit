/**
 * Independent reader for MaxMind DB files (GeoLite2-Country / GeoLite2-ASN).
 *
 * The DNS page adds a "Location" and a "Provider" column to A and AAAA
 * records by looking each address up in the two .mmdb files it downloads from
 * `/data/`. To check those columns the suite needs its own answer, so this
 * file reads the same databases with a reader written from the format
 * specification (https://maxmind.github.io/MaxMind-DB/), not from the page's
 * reader in `frontend/public/js/geoip.js`:
 *
 *  - addresses are BigInt values, bits are taken by division, not bit arrays;
 *  - an IPv4 address is looked up below `::/96`, as the specification says
 *    (the page walks `::ffff:0:0/96`, an alias in GeoLite2 files);
 *  - the data section is decoded with Node `Buffer` readers.
 */

const MARKER = Buffer.from([0xab, 0xcd, 0xef, ...Buffer.from('MaxMind.com', 'latin1')]);

interface Decoded { value: unknown; next: number }

export class Mmdb {
  private readonly nodeCount: number;
  private readonly recordBits: number;
  private readonly nodeBytes: number;
  private readonly ipVersion: number;
  /** Absolute offset of the data section (after the 16 zero bytes that follow the tree). */
  private readonly dataStart: number;
  private ipv4Root: number | null = null;
  private readonly file: Buffer;

  constructor(file: Buffer) {
    this.file = file;
    const marker = file.lastIndexOf(MARKER);
    if (marker < 0) throw new Error('not a MaxMind DB file: metadata marker missing');
    // Pointers do not occur in the metadata section, so the base is irrelevant there.
    const meta = this.decode(marker + MARKER.length, marker + MARKER.length).value as Record<string, number>;
    this.nodeCount = Number(meta.node_count);
    this.recordBits = Number(meta.record_size);
    this.ipVersion = Number(meta.ip_version);
    this.nodeBytes = (this.recordBits * 2) / 8;
    this.dataStart = this.nodeCount * this.nodeBytes + 16;
  }

  /** The record stored for `ip`, or null when the database has none. */
  lookup(ip: string): Record<string, unknown> | null {
    const parsed = parseIp(ip);
    if (!parsed) return null;
    let node = 0;
    let bitsLeft = parsed.bits;
    if (parsed.bits === 32 && this.ipVersion === 6) node = this.rootForIpv4();
    if (parsed.bits === 128 && this.ipVersion === 4) return null;
    while (bitsLeft > 0 && node < this.nodeCount) {
      bitsLeft--;
      const bit = Number((parsed.value / 2n ** BigInt(bitsLeft)) % 2n);
      node = this.child(node, bit);
    }
    if (node <= this.nodeCount) return null; // still inside the tree, or the "no data" value
    const offset = node - this.nodeCount - 16 + this.dataStart;
    return this.decode(offset, this.dataStart).value as Record<string, unknown>;
  }

  private rootForIpv4(): number {
    if (this.ipv4Root === null) {
      let node = 0;
      for (let i = 0; i < 96 && node < this.nodeCount; i++) node = this.child(node, 0);
      this.ipv4Root = node;
    }
    return this.ipv4Root;
  }

  private child(node: number, side: number): number {
    const at = node * this.nodeBytes;
    const f = this.file;
    if (this.recordBits === 24) return f.readUIntBE(at + side * 3, 3);
    if (this.recordBits === 32) return f.readUInt32BE(at + side * 4);
    if (this.recordBits === 28) {
      const middle = f[at + 3];
      return side === 0
        ? Math.floor(middle / 16) * 2 ** 24 + f.readUIntBE(at, 3)
        : (middle % 16) * 2 ** 24 + f.readUIntBE(at + 4, 3);
    }
    throw new Error(`unsupported MaxMind DB record size ${this.recordBits}`);
  }

  private decode(offset: number, pointerBase: number): Decoded {
    const f = this.file;
    const control = f[offset++];
    let type = Math.floor(control / 32);

    if (type === 1) {
      const width = Math.floor(control / 8) % 4;
      const high = control % 8;
      let target: number;
      if (width === 0) target = high * 256 + f[offset];
      else if (width === 1) target = 2048 + high * 65536 + f.readUInt16BE(offset);
      else if (width === 2) target = 526336 + high * 16777216 + f.readUIntBE(offset, 3);
      else target = f.readUInt32BE(offset);
      return { value: this.decode(pointerBase + target, pointerBase).value, next: offset + width + 1 };
    }

    if (type === 0) type = 7 + f[offset++];

    let size = control % 32;
    if (size === 29) { size = 29 + f[offset]; offset += 1; }
    else if (size === 30) { size = 285 + f.readUInt16BE(offset); offset += 2; }
    else if (size === 31) { size = 65821 + f.readUIntBE(offset, 3); offset += 3; }

    switch (type) {
      case 2: return { value: f.toString('utf8', offset, offset + size), next: offset + size };
      case 3: return { value: f.readDoubleBE(offset), next: offset + 8 };
      case 4: return { value: f.subarray(offset, offset + size), next: offset + size };
      case 5: case 6: case 9: case 10: {
        let n = 0n;
        for (let i = 0; i < size; i++) n = n * 256n + BigInt(f[offset + i]);
        return { value: n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n, next: offset + size };
      }
      case 8: return { value: size === 0 ? 0 : f.readIntBE(offset, size), next: offset + size };
      case 7: {
        const map: Record<string, unknown> = {};
        for (let i = 0; i < size; i++) {
          const key = this.decode(offset, pointerBase);
          const val = this.decode(key.next, pointerBase);
          map[String(key.value)] = val.value;
          offset = val.next;
        }
        return { value: map, next: offset };
      }
      case 11: {
        const list: unknown[] = [];
        for (let i = 0; i < size; i++) {
          const item = this.decode(offset, pointerBase);
          list.push(item.value);
          offset = item.next;
        }
        return { value: list, next: offset };
      }
      case 14: return { value: size !== 0, next: offset }; // boolean: the value is the size field
      case 15: return { value: f.readFloatBE(offset), next: offset + 4 };
      default: throw new Error(`unsupported MaxMind DB data type ${type} at offset ${offset}`);
    }
  }
}

/** Address as an integer plus its width in bits; null when it is not an IP address. */
export function parseIp(text: string): { value: bigint; bits: 32 | 128 } | null {
  const ip = text.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    const octets = ip.split('.').map(Number);
    if (octets.some(o => o > 255)) return null;
    return { value: octets.reduce((acc, o) => acc * 256n + BigInt(o), 0n), bits: 32 };
  }
  if (!ip.includes(':') || !/^[0-9a-f:]+$/i.test(ip)) return null;
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...head, ...Array.from({ length: halves.length === 2 ? missing : 0 }, () => '0'), ...tail];
  if (groups.some(g => g.length === 0 || g.length > 4)) return null;
  return { value: groups.reduce((acc, g) => acc * 65536n + BigInt(parseInt(g, 16)), 0n), bits: 128 };
}
