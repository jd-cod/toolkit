/**
 * IPv6 subnet math for the Subnet Calculator. Addresses are 128-bit, so
 * everything is BigInt. `BigInt(n)` is used instead of `1n` literals because
 * the frontend compiles to ES2017.
 */

const ZERO = BigInt(0);
const ONE = BigInt(1);
const BITS = BigInt(128);
const GROUP = BigInt(16);
const ALL_ONES = (ONE << BITS) - ONE;

export interface Ipv6Subnet {
  cidr: string;
  prefix: number;
  address: string;
  network: string;
  networkExpanded: string;
  first: string;
  last: string;
  /** Exact count as a decimal string; it can have 39 digits. */
  totalAddresses: string;
  /** Rounded, readable form such as "18.4 quintillion". */
  totalReadable: string;
  /** Number of /64 networks inside the block, or '' when the prefix is longer than /64. */
  subnets64: string;
  type: string;
  typeNote: string;
  /** ip6.arpa zone for reverse DNS delegation, or '' when the prefix is not on a 4-bit boundary. */
  reverseZone: string;
  notes: string[];
}

/** Parses one IPv6 address (with optional embedded IPv4 tail) to a BigInt, or null. */
export function parseIpv6(input: string): bigint | null {
  let text = input.trim().toLowerCase();
  if (!text || text.length > 45) return null;
  const zone = text.indexOf('%');
  if (zone !== -1) text = text.slice(0, zone);

  // Rewrite a dotted IPv4 tail (::ffff:192.0.2.1) as two hex groups.
  const v4 = /^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4) {
    const octets = v4.slice(2).map(Number);
    if (octets.some(octet => octet > 255)) return null;
    text = `${v4[1]}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }

  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;

  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (groups.length !== 8) return null;
  let value = ZERO;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << GROUP) | BigInt(parseInt(group, 16));
  }
  return value;
}

function groupsOf(value: bigint): string[] {
  const groups: string[] = [];
  for (let i = 7; i >= 0; i--) groups.push(((value >> (GROUP * BigInt(i))) & BigInt(0xffff)).toString(16));
  return groups;
}

export function expandIpv6(value: bigint): string {
  return groupsOf(value).map(group => group.padStart(4, '0')).join(':');
}

/** Canonical short form (RFC 5952): lowercase, longest zero run of two or more groups collapsed. */
export function formatIpv6(value: bigint): string {
  const groups = groupsOf(value);
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] !== '0') continue;
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > bestLength) { bestStart = i; bestLength = j - i; }
    i = j;
  }
  if (bestLength < 2) return groups.join(':');
  return `${groups.slice(0, bestStart).join(':')}::${groups.slice(bestStart + bestLength).join(':')}`;
}

const SCALE = ['', 'thousand', 'million', 'billion', 'trillion', 'quadrillion', 'quintillion', 'sextillion', 'septillion', 'octillion', 'nonillion', 'decillion', 'undecillion'];

export function readableCount(value: bigint): string {
  const digits = value.toString();
  if (digits.length <= 6) return digits.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const scale = Math.floor((digits.length - 1) / 3);
  const lead = digits.length - scale * 3;
  const decimal = digits.slice(lead, lead + 1);
  return `${digits.slice(0, lead)}${decimal !== '0' ? `.${decimal}` : ''} ${SCALE[scale] || `× 10^${scale * 3}`}`;
}

const RANGES: Array<{ cidr: string; type: string; note: string }> = [
  { cidr: '::1/128', type: 'Loopback', note: 'The local host.' },
  { cidr: '::/128', type: 'Unspecified', note: 'Used as a source before an address is assigned.' },
  { cidr: '::ffff:0:0/96', type: 'IPv4-mapped', note: 'Represents an IPv4 address inside IPv6 sockets. Not routed.' },
  { cidr: '64:ff9b::/96', type: 'NAT64', note: 'Well-known prefix for IPv6 to IPv4 translation.' },
  { cidr: '2001:db8::/32', type: 'Documentation', note: 'Reserved for examples. Never routed on the internet.' },
  { cidr: '2001::/32', type: 'Teredo', note: 'Teredo tunnelling.' },
  { cidr: '2002::/16', type: '6to4', note: '6to4 tunnelling (deprecated).' },
  { cidr: 'fc00::/7', type: 'Unique local (ULA)', note: 'Private addressing, like RFC 1918 in IPv4. Not routed on the internet.' },
  { cidr: 'fe80::/10', type: 'Link-local', note: 'Valid on one network segment only. Every interface has one.' },
  { cidr: 'ff00::/8', type: 'Multicast', note: 'One-to-many delivery. IPv6 has no broadcast.' },
  { cidr: '2000::/3', type: 'Global unicast', note: 'Publicly routable address space.' },
];

function contains(cidr: string, value: bigint): boolean {
  const [base, length] = cidr.split('/');
  const network = parseIpv6(base);
  if (network === null) return false;
  const shift = BITS - BigInt(Number(length));
  return (value >> shift) === (network >> shift);
}

/** Parses `2001:db8::/48` (or a bare address, treated as /128). Returns null when invalid. */
export function parseIpv6Cidr(input: string): Ipv6Subnet | null {
  const text = input.trim();
  const slash = text.indexOf('/');
  const addressText = slash === -1 ? text : text.slice(0, slash);
  const prefixText = slash === -1 ? '128' : text.slice(slash + 1).trim();
  if (!/^\d{1,3}$/.test(prefixText)) return null;
  const prefix = Number(prefixText);
  const address = parseIpv6(addressText);
  if (address === null || prefix > 128) return null;

  const hostBits = BITS - BigInt(prefix);
  const hostMask = prefix === 0 ? ALL_ONES : (ONE << hostBits) - ONE;
  const network = address & (ALL_ONES ^ hostMask);
  const last = network | hostMask;
  const total = ONE << hostBits;
  const range = RANGES.find(item => contains(item.cidr, network)) || { type: 'Reserved', note: 'Not in a range that is currently allocated.' };

  let reverseZone = '';
  if (prefix % 4 === 0 && prefix > 0) {
    const nibbles = expandIpv6(network).replace(/:/g, '').slice(0, prefix / 4);
    reverseZone = `${nibbles.split('').reverse().join('.')}.ip6.arpa`;
  }

  const notes: string[] = [];
  if (prefix === 64) notes.push('/64 is the standard size for one network segment. SLAAC needs exactly /64.');
  else if (prefix > 64 && prefix < 127) notes.push('Prefixes longer than /64 break SLAAC. Use them only with static addressing or DHCPv6.');
  else if (prefix === 127) notes.push('/127 is recommended for point-to-point links (RFC 6164).');
  else if (prefix === 128) notes.push('/128 is a single address.');
  else if (prefix === 48) notes.push('/48 is the usual allocation for one site: 65,536 networks of size /64.');
  else if (prefix === 56) notes.push('/56 is a common home or small-site allocation: 256 networks of size /64.');
  if (address !== network) notes.push(`The address you entered has host bits set. The network starts at ${formatIpv6(network)}.`);

  return {
    cidr: `${formatIpv6(network)}/${prefix}`,
    prefix,
    address: formatIpv6(address),
    network: formatIpv6(network),
    networkExpanded: expandIpv6(network),
    first: formatIpv6(network),
    last: formatIpv6(last),
    totalAddresses: total.toString(),
    totalReadable: readableCount(total),
    subnets64: prefix <= 64 ? readableCount(ONE << BigInt(64 - prefix)) : '',
    type: range.type,
    typeNote: range.note,
    reverseZone,
    notes,
  };
}

/** The first `count` subnets of size `newPrefix` inside `cidr`, for planning. */
export function splitIpv6(cidr: string, newPrefix: number, count = 8): string[] {
  const parent = parseIpv6Cidr(cidr);
  if (!parent || !Number.isInteger(newPrefix) || newPrefix <= parent.prefix || newPrefix > 128) return [];
  const base = parseIpv6(parent.network);
  if (base === null) return [];
  const step = ONE << (BITS - BigInt(newPrefix));
  const available = ONE << BigInt(newPrefix - parent.prefix);
  const out: string[] = [];
  for (let i = 0; i < count && BigInt(i) < available; i++) out.push(`${formatIpv6(base + step * BigInt(i))}/${newPrefix}`);
  return out;
}
