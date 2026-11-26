import { buildReportHtml } from './report-html';

function ipToInt(ip: string): number | null {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function maskFromPrefix(prefix: number): number {
  if (prefix === 0) return 0;
  return (~0 << (32 - prefix)) >>> 0;
}

export function parseCIDR(input: string) {
  input = input.trim();
  let ip: number | null, prefix: number;
  if (input.includes('/')) {
    const [ipPart, prefixPart] = input.split('/');
    ip = ipToInt(ipPart); prefix = parseInt(prefixPart, 10);
  } else if (input.includes(' ')) {
    const parts = input.split(/\s+/);
    ip = ipToInt(parts[0]); const mask = ipToInt(parts[1]);
    if (mask === null) return null;
    let bits = 0, m = mask;
    while (m & 0x80000000) { bits++; m = (m << 1) >>> 0; }
    prefix = bits;
  } else { ip = ipToInt(input); prefix = 32; }

  if (ip === null || isNaN(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = maskFromPrefix(prefix);
  const wildcard = (~mask) >>> 0;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;
  const totalHosts = Math.pow(2, 32 - prefix);
  const usableHosts = prefix >= 31 ? (prefix === 32 ? 1 : 2) : totalHosts - 2;
  const firstHost = prefix === 32 ? network : prefix === 31 ? network : (network + 1) >>> 0;
  const lastHost = prefix === 32 ? network : prefix === 31 ? broadcast : (broadcast - 1) >>> 0;

  const first = (network >>> 24) & 255;
  const second = (network >>> 16) & 255;
  let ipClass = 'Class A', ipType = '🌐 Public';
  if (first < 128) ipClass = 'Class A (0–127)';
  else if (first < 192) ipClass = 'Class B (128–191)';
  else if (first < 224) ipClass = 'Class C (192–223)';
  else if (first < 240) ipClass = 'Class D Multicast';
  else ipClass = 'Class E Reserved';

  if (first === 10) ipType = '🏠 Private (RFC 1918)';
  else if (first === 172 && second >= 16 && second <= 31) ipType = '🏠 Private (RFC 1918)';
  else if (first === 192 && second === 168) ipType = '🏠 Private (RFC 1918)';
  else if (first === 127) ipType = '🔄 Loopback';
  else if (first === 169 && second === 254) ipType = '🔗 Link-Local';

  return {
    cidr: `${intToIp(network)}/${prefix}`, ip, prefix, mask, wildcard, network, broadcast,
    firstHost, lastHost, totalHosts, usableHosts,
    networkStr: intToIp(network), broadcastStr: intToIp(broadcast),
    firstHostStr: intToIp(firstHost), lastHostStr: intToIp(lastHost),
    maskStr: intToIp(mask), wildcardStr: intToIp(wildcard),
    ipClass, ipType,
  };
}

export type SubnetResult = NonNullable<ReturnType<typeof parseCIDR>>;

/** A subnet calculation as it is shared: only the inputs, since the result is recomputed from them. */
export interface SubnetSnapshot {
  cidr: string;
  aws_mode: boolean;
  checked_at_utc: string;
}

export function normalizeSubnetSnapshot(raw: unknown): SubnetSnapshot {
  const d = (raw ?? {}) as Partial<SubnetSnapshot>;
  return {
    cidr: typeof d.cidr === 'string' ? d.cidr : '',
    aws_mode: Boolean(d.aws_mode),
    checked_at_utc: typeof d.checked_at_utc === 'string' ? d.checked_at_utc : new Date().toISOString(),
  };
}

/** AWS reserves five addresses in every subnet. */
export function awsUsableHosts(result: SubnetResult) {
  return Math.max(0, result.usableHosts - 5);
}

export function subnetDetailRows(result: SubnetResult, awsMode: boolean): [string, string][] {
  return [
    ['Network Address', result.networkStr], ['Broadcast Address', result.broadcastStr],
    ['First Usable Host', result.firstHostStr], ['Last Usable Host', result.lastHostStr],
    ['Subnet Mask', result.maskStr], ['Wildcard Mask', result.wildcardStr],
    ['Total Addresses', result.totalHosts.toLocaleString()], ['Usable Hosts', result.usableHosts.toLocaleString()],
    ...(awsMode ? [['AWS Usable Hosts', awsUsableHosts(result).toLocaleString()] as [string, string]] : []),
    ['CIDR Notation', result.cidr], ['IP Class', result.ipClass], ['IP Type', result.ipType],
  ];
}

export function buildSubnetSummary(result: SubnetResult, awsMode: boolean) {
  return [
    `CIDR: ${result.cidr}`,
    `Netmask: ${result.maskStr}`,
    `Wildcard: ${result.wildcardStr}`,
    `Network: ${result.networkStr}`,
    `Broadcast: ${result.broadcastStr}`,
    `Usable Range: ${result.firstHostStr} - ${result.lastHostStr}`,
    `Total Hosts: ${result.totalHosts}`,
    `Usable Hosts: ${result.usableHosts}`,
    ...(awsMode ? [`AWS Usable Hosts: ${awsUsableHosts(result)}`] : []),
  ].join('\n');
}

export function buildSubnetReportHtml(result: SubnetResult, awsMode: boolean, checkedAt?: string) {
  const usable = awsMode ? awsUsableHosts(result) : result.usableHosts;
  return buildReportHtml({
    title: 'Subnet Report',
    subject: result.cidr,
    subtitle: awsMode ? 'AWS mode: five addresses reserved per subnet' : undefined,
    checkedAt,
    timeLabel: 'Generated at',
    cards: [
      { label: 'Network CIDR', value: result.cidr, mono: true },
      { label: awsMode ? 'AWS Usable Hosts' : 'Usable Hosts', value: usable.toLocaleString() },
      { label: 'Total Addresses', value: result.totalHosts.toLocaleString() },
      { label: 'Prefix Length', value: `/${result.prefix}` },
    ],
    sections: [{ title: 'Subnet Details', rows: subnetDetailRows(result, awsMode) }],
  });
}
