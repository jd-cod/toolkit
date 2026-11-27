import type { Rng } from '../_support/rng';

/**
 * Independent subnet arithmetic.
 *
 * The page works with 32-bit bitwise operators; this file uses BigInt
 * arithmetic and written-out rules instead, so a mistake in one is not
 * repeated in the other.
 */

export interface SubnetExpectation {
  cidr: string;
  prefix: number;
  network: string;
  broadcast: string;
  firstHost: string;
  lastHost: string;
  mask: string;
  wildcard: string;
  totalAddresses: bigint;
  usableHosts: bigint;
  awsUsableHosts: bigint;
  ipClass: string;
  ipType: string;
}

export function ipToBig(ip: string): bigint {
  return ip.split('.').reduce((acc, octet) => acc * 256n + BigInt(octet), 0n);
}

export function bigToIp(value: bigint): string {
  return [3n, 2n, 1n, 0n].map(shift => String((value / 256n ** shift) % 256n)).join('.');
}

export function maskForPrefix(prefix: number): bigint {
  return 2n ** 32n - 2n ** BigInt(32 - prefix);
}

export function expectedSubnet(ip: string, prefix: number): SubnetExpectation {
  const size = 2n ** BigInt(32 - prefix);
  const address = ipToBig(ip);
  const network = address - (address % size);
  const broadcast = network + size - 1n;

  // /31 is a point-to-point link (RFC 3021): both addresses are usable.
  // /32 is a single host.
  let usable: bigint, first: bigint, last: bigint;
  if (prefix === 32) { usable = 1n; first = network; last = network; }
  else if (prefix === 31) { usable = 2n; first = network; last = broadcast; }
  else { usable = size - 2n; first = network + 1n; last = broadcast - 1n; }

  const [a, b] = bigToIp(network).split('.').map(Number);
  let ipClass: string;
  if (a <= 127) ipClass = 'Class A (0–127)';
  else if (a <= 191) ipClass = 'Class B (128–191)';
  else if (a <= 223) ipClass = 'Class C (192–223)';
  else if (a <= 239) ipClass = 'Class D Multicast';
  else ipClass = 'Class E Reserved';

  let ipType = 'Public';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) ipType = 'Private (RFC 1918)';
  else if (a === 127) ipType = 'Loopback';
  else if (a === 169 && b === 254) ipType = 'Link-Local';

  const mask = maskForPrefix(prefix);
  return {
    cidr: `${bigToIp(network)}/${prefix}`,
    prefix,
    network: bigToIp(network),
    broadcast: bigToIp(broadcast),
    firstHost: bigToIp(first),
    lastHost: bigToIp(last),
    mask: bigToIp(mask),
    wildcard: bigToIp(2n ** 32n - 1n - mask),
    totalAddresses: size,
    usableHosts: usable,
    awsUsableHosts: usable > 5n ? usable - 5n : 0n,
    ipClass,
    ipType,
  };
}

/** `4294967296n` → `4,294,967,296` (the page formats counts for en-US). */
export function grouped(value: bigint): string {
  return value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export function randomIp(rng: Rng): string {
  return [rng.int(0, 255), rng.int(0, 255), rng.int(0, 255), rng.int(0, 255)].join('.');
}

/** Inputs a user could type that are not a valid IPv4 network. */
export const INVALID_INPUTS: { input: string; why: string }[] = [
  { input: '10.0.0.0/33', why: 'prefix above 32' },
  { input: '10.0.0.0/-1', why: 'negative prefix' },
  { input: '256.1.1.1/24', why: 'octet above 255' },
  { input: '10.0.0/24', why: 'three octets' },
  { input: '10.0.0.0.0/24', why: 'five octets' },
  { input: '10.0.0.0/abc', why: 'prefix is not a number' },
  { input: 'not-an-ip', why: 'free text' },
  { input: '10.0.0.0/24/8', why: 'two prefixes' },
  { input: '10..0.1/24', why: 'empty octet' },
  { input: '1e1.0.0.0/8', why: 'octet in exponent notation' },
  { input: '0x10.0.0.0/8', why: 'octet in hexadecimal' },
  { input: '10.0.0.0/8abc', why: 'trailing text after the prefix' },
  { input: '10.0.0.0/2.5', why: 'fractional prefix' },
  { input: '10.0.0.0 255.0.255.0', why: 'netmask with a hole in it' },
  { input: '10.0.0.0 255.255.255.256', why: 'netmask octet above 255' },
  { input: '-1.0.0.0/8', why: 'negative octet' },
  { input: '2001:db8::/32', why: 'IPv6 (the tool is IPv4 only)' },
];
