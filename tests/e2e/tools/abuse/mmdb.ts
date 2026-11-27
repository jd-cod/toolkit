/**
 * A small reader for MaxMind DB files (https://maxmind.github.io/MaxMind-DB/),
 * written from the format specification for the tests only.
 *
 * The page reads GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb in the browser
 * with its own reader. This one is independent of it on purpose: it walks the
 * search tree with BigInt address values and looks IPv4 addresses up at
 * ::/96 (the canonical place), so a mistake in one reader shows up as a
 * difference between the page and the oracle.
 */

const MARKER = Buffer.concat([Buffer.from([0xab, 0xcd, 0xef]), Buffer.from('MaxMind.com', 'latin1')]);

type Value = string | number | bigint | boolean | Buffer | Value[] | { [key: string]: Value } | null;

export class MmdbReader {
  private readonly nodeCount: number;
  private readonly recordSize: number;
  private readonly treeBytes: number;
  private readonly ipVersion: number;
  readonly databaseType: string;

  constructor(private readonly file: Buffer) {
    const at = file.lastIndexOf(MARKER);
    if (at < 0) throw new Error('not a MaxMind DB file: metadata marker missing');
    const start = at + MARKER.length;
    const metadata = this.decode(start, start).value as { [key: string]: Value };
    this.nodeCount = Number(metadata.node_count);
    this.recordSize = Number(metadata.record_size);
    this.ipVersion = Number(metadata.ip_version);
    this.databaseType = String(metadata.database_type);
    this.treeBytes = (this.nodeCount * this.recordSize * 2) / 8;
  }

  /** The record stored for `ip`, or null when the database has none. */
  lookup(ip: string): { [key: string]: Value } | null {
    const address = toBigInt(ip);
    if (address === null) return null;
    const bits = this.ipVersion === 6 ? 128 : 32;
    if (this.ipVersion === 4 && ip.includes(':')) return null;
    let node = 0;
    for (let position = bits - 1; position >= 0 && node < this.nodeCount; position--) {
      const bit = Number((address.value >> BigInt(position)) & 1n);
      node = this.record(node, bit);
    }
    if (node <= this.nodeCount) return null;
    // Data pointers count from the start of the data section, which follows 16 zero bytes.
    const dataStart = this.treeBytes + 16;
    const offset = node - this.nodeCount - 16 + dataStart;
    return this.decode(offset, dataStart).value as { [key: string]: Value };
  }

  private record(node: number, side: number): number {
    const base = node * (this.recordSize / 4);
    const f = this.file;
    if (this.recordSize === 24) return f.readUIntBE(base + side * 3, 3);
    if (this.recordSize === 32) return f.readUInt32BE(base + side * 4);
    if (this.recordSize === 28) {
      const middle = f[base + 3];
      return side === 0
        ? ((middle >> 4) * 2 ** 24) + f.readUIntBE(base, 3)
        : ((middle & 0x0f) * 2 ** 24) + f.readUIntBE(base + 4, 3);
    }
    throw new Error(`unsupported record size ${this.recordSize}`);
  }

  private decode(offset: number, pointerBase: number): { value: Value; next: number } {
    const f = this.file;
    const control = f[offset++];
    let type = control >> 5;
    if (type === 1) {
      const sizeClass = (control >> 3) & 3;
      const low = control & 7;
      let pointer: number;
      if (sizeClass === 0) pointer = low * 256 + f[offset];
      else if (sizeClass === 1) pointer = 2048 + low * 65536 + f.readUInt16BE(offset);
      else if (sizeClass === 2) pointer = 526336 + low * 16777216 + f.readUIntBE(offset, 3);
      else pointer = f.readUInt32BE(offset);
      return { value: this.decode(pointerBase + pointer, pointerBase).value, next: offset + sizeClass + 1 };
    }
    if (type === 0) type = 7 + f[offset++];
    let size = control & 0x1f;
    if (size === 29) { size = 29 + f[offset]; offset += 1; }
    else if (size === 30) { size = 285 + f.readUInt16BE(offset); offset += 2; }
    else if (size === 31) { size = 65821 + f.readUIntBE(offset, 3); offset += 3; }

    switch (type) {
      case 2: return { value: f.toString('utf8', offset, offset + size), next: offset + size };
      case 3: return { value: f.readDoubleBE(offset), next: offset + 8 };
      case 4: return { value: f.subarray(offset, offset + size), next: offset + size };
      case 5: case 6: return { value: size === 0 ? 0 : f.readUIntBE(offset, size), next: offset + size };
      case 8: return { value: size === 0 ? 0 : f.readIntBE(offset, size), next: offset + size };
      case 9: case 10: {
        let big = 0n;
        for (let i = 0; i < size; i++) big = big * 256n + BigInt(f[offset + i]);
        return { value: big, next: offset + size };
      }
      case 7: {
        const map: { [key: string]: Value } = {};
        for (let i = 0; i < size; i++) {
          const key = this.decode(offset, pointerBase);
          const item = this.decode(key.next, pointerBase);
          map[String(key.value)] = item.value;
          offset = item.next;
        }
        return { value: map, next: offset };
      }
      case 11: {
        const list: Value[] = [];
        for (let i = 0; i < size; i++) {
          const item = this.decode(offset, pointerBase);
          list.push(item.value);
          offset = item.next;
        }
        return { value: list, next: offset };
      }
      case 14: return { value: size !== 0, next: offset };
      case 15: return { value: f.readFloatBE(offset), next: offset + 4 };
      default: return { value: null, next: offset + size };
    }
  }
}

/** The address as one number: 32 bits for IPv4 (placed at ::/96 in an IPv6 tree), 128 bits for IPv6. */
function toBigInt(ip: string): { value: bigint } | null {
  if (!ip.includes(':')) {
    const octets = ip.split('.');
    if (octets.length !== 4 || octets.some(octet => !/^\d{1,3}$/.test(octet) || Number(octet) > 255)) return null;
    return { value: octets.reduce((sum, octet) => sum * 256n + BigInt(octet), 0n) };
  }
  const [head, tail, extra] = ip.split('::');
  if (extra !== undefined) return null;
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = tail === undefined ? left : [...left, ...new Array(8 - left.length - right.length).fill('0'), ...right];
  if (groups.length !== 8 || groups.some(group => !/^[0-9a-fA-F]{1,4}$/.test(group))) return null;
  return { value: groups.reduce((sum, group) => sum * 65536n + BigInt(parseInt(group, 16)), 0n) };
}

export interface GeoAnswer { country?: string; country_code?: string; asn?: number; asn_org?: string }

/** Country and ASN of `ip` as the two GeoLite2 files state them; keys are absent when the file has no record. */
export function geoFacts(country: MmdbReader, asn: MmdbReader, ip: string): GeoAnswer {
  const out: GeoAnswer = {};
  const place = country.lookup(ip) as any;
  if (place?.country?.iso_code) {
    out.country_code = place.country.iso_code;
    if (place.country.names?.en) out.country = place.country.names.en;
  }
  const network = asn.lookup(ip) as any;
  if (network?.autonomous_system_number) {
    out.asn = network.autonomous_system_number;
    if (network.autonomous_system_organization) out.asn_org = network.autonomous_system_organization;
  }
  return out;
}
