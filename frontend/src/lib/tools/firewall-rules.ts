import { psQuote, shQuote } from './shell.ts';

/** One firewall rule, written for ufw, firewalld, nftables, iptables and Windows Firewall. */

export type FirewallAction = 'allow' | 'deny' | 'reject';
export type FirewallDirection = 'in' | 'out';
export type FirewallProtocol = 'tcp' | 'udp' | 'both' | 'any';

export interface FirewallRule {
  /** deny drops silently, reject answers with an error. */
  action: FirewallAction;
  direction: FirewallDirection;
  protocol: FirewallProtocol;
  /** Destination ports: `22`, `80,443`, `8000-8100` or a mix. Empty means all ports. */
  ports: string;
  /** Remote address: the source of an inbound rule, the destination of an outbound one. IPv4, IPv6 or CIDR. Empty means any. */
  source: string;
  /** Network interface name. Empty means all interfaces. */
  iface: string;
  /** Comment, also used as the rule name on Windows. */
  comment: string;
}

export const FIREWALL_DEFAULTS: FirewallRule = {
  action: 'allow',
  direction: 'in',
  protocol: 'tcp',
  ports: '22',
  source: '203.0.113.10',
  iface: '',
  comment: 'Office SSH',
};

export type FirewallToolKey = 'ufw' | 'firewalld' | 'nftables' | 'iptables' | 'powershell' | 'netsh';

export interface FirewallOutput {
  key: FirewallToolKey;
  label: string;
  /** One command per line. Empty when the tool cannot express the rule. */
  commands: string[];
  /** How the rule survives a reboot. */
  persistence: string;
  notes: string[];
}

export interface FirewallResult {
  /** Empty when there are errors: a rule built from partly valid input could match more than intended. */
  outputs: FirewallOutput[];
  errors: string[];
  warnings: string[];
}

interface PortItem {
  from: number;
  to: number;
}

interface Address {
  family: 4 | 6;
  /** Validated text, safe to print unquoted in a shell. */
  text: string;
  /** A /0 prefix: every address of that family. */
  any: boolean;
}

type Proto = 'tcp' | 'udp';

interface Context {
  action: FirewallAction;
  inbound: boolean;
  protocol: FirewallProtocol;
  /** Protocols to write a rule for. `null` is a rule without a protocol match. */
  protos: Array<Proto | null>;
  ports: PortItem[];
  address: Address | null;
  iface: string;
  comment: string;
}

const IFACE_PATTERN = /^[A-Za-z0-9_.:@-]{1,15}$/;
/**
 * Printable ASCII without " \ % | $ and the backtick. nftables strings and
 * Windows rule names cannot carry the first four, and the last two would be
 * expanded when the netsh line is pasted into PowerShell.
 */
const COMMENT_PATTERN = /^[ !#&-[\]-_a-{}~]{1,100}$/;
/** iptables multiport and ufw take at most 15 ports per rule. A range counts as two. */
const MULTIPORT_LIMIT = 15;

const LOCKOUT_PORTS: Array<[number, string]> = [[22, 'SSH'], [3389, 'RDP']];
const EXPOSED_PORTS: Array<[number, string, string]> = [
  [3306, 'MySQL', 'a database'],
  [5432, 'PostgreSQL', 'a database'],
  [1433, 'SQL Server', 'a database'],
  [1521, 'Oracle', 'a database'],
  [27017, 'MongoDB', 'a database'],
  [9200, 'Elasticsearch', 'a database'],
  [5984, 'CouchDB', 'a database'],
  [6379, 'Redis', 'a cache'],
  [11211, 'Memcached', 'a cache'],
  [2375, 'Docker API', 'the Docker API'],
];

function parsePorts(text: string, errors: string[]): PortItem[] {
  const items: PortItem[] = [];
  const tokens = String(text ?? '').replace(/\s*([-:])\s*/g, '$1').split(/[\s,]+/).filter(Boolean);
  for (const token of tokens) {
    const match = /^(\d{1,5})(?:[-:](\d{1,5}))?$/.exec(token);
    if (!match) {
      errors.push(`Port "${token.slice(0, 20)}" is not valid. Use numbers, lists (80,443) and ranges (8000-8100).`);
      continue;
    }
    const from = Number(match[1]);
    const to = match[2] === undefined ? from : Number(match[2]);
    if (from < 1 || from > 65535 || to < 1 || to > 65535) errors.push(`Port ${token} is out of range. Ports go from 1 to 65535.`);
    else if (to < from) errors.push(`Port range ${token} runs backwards. Write the lower port first.`);
    else items.push({ from, to });
  }
  // Sort, drop duplicates and fold overlapping ranges into one.
  items.sort((a, b) => a.from - b.from || a.to - b.to);
  const merged: PortItem[] = [];
  for (const item of items) {
    const last = merged[merged.length - 1];
    if (last && item.from <= last.to) last.to = Math.max(last.to, item.to);
    else merged.push({ ...item });
  }
  return merged;
}

function parseIpv4(text: string): number[] | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map(part => (/^(?:0|[1-9]\d{0,2})$/.test(part) ? Number(part) : 256));
  return octets.every(octet => octet <= 255) ? octets : null;
}

/** Returns the eight 16-bit groups, or null. */
function parseIpv6(text: string): number[] | null {
  if (!/^[0-9A-Fa-f:.]{2,45}$/.test(text)) return null;
  let body = text;
  if (body.includes('.')) {
    // IPv4 in the last 32 bits, as in ::ffff:192.0.2.1
    const cut = body.lastIndexOf(':');
    const tail = cut === -1 ? null : parseIpv4(body.slice(cut + 1));
    if (!tail) return null;
    body = `${body.slice(0, cut + 1)}${((tail[0] << 8) | tail[1]).toString(16)}:${((tail[2] << 8) | tail[3]).toString(16)}`;
  }
  const halves = body.split('::');
  if (halves.length > 2) return null;
  const groups = (half: string) => (half === '' ? [] : half.split(':').map(group => (/^[0-9A-Fa-f]{1,4}$/.test(group) ? parseInt(group, 16) : -1)));
  const left = groups(halves[0]);
  const right = halves.length === 2 ? groups(halves[1]) : [];
  if (left.includes(-1) || right.includes(-1)) return null;
  if (halves.length === 1) return left.length === 8 ? left : null;
  const missing = 8 - left.length - right.length;
  return missing < 1 ? null : [...left, ...new Array<number>(missing).fill(0), ...right];
}

/** RFC 5952 form: lower case, the longest run of zero groups written as `::`. */
function formatIpv6(groups: number[]): string {
  let bestStart = -1;
  let bestLength = 1;
  for (let start = 0; start < 8; start++) {
    let length = 0;
    while (start + length < 8 && groups[start + length] === 0) length++;
    if (length > bestLength) {
      bestStart = start;
      bestLength = length;
    }
    start += length;
  }
  const hex = groups.map(group => group.toString(16));
  if (bestStart === -1) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLength).join(':')}`;
}

/** Zero the bits after the prefix. `width` is the size of one part in bits. */
function maskParts(parts: number[], prefix: number, width: number): number[] {
  const full = (1 << width) - 1;
  return parts.map((part, index) => {
    const keep = Math.min(width, Math.max(0, prefix - index * width));
    return part & (full ^ ((1 << (width - keep)) - 1));
  });
}

function parseAddress(input: string, errors: string[], warnings: string[]): Address | null {
  const text = String(input ?? '').trim();
  if (!text) return null;
  const shown = text.slice(0, 60);
  const slash = text.indexOf('/');
  const host = slash === -1 ? text : text.slice(0, slash);
  const prefixText = slash === -1 ? null : text.slice(slash + 1);
  if (prefixText !== null && !/^\d{1,3}$/.test(prefixText)) {
    errors.push(`"${shown}" is not a valid address. The part after / must be a prefix length such as 24.`);
    return null;
  }
  const prefix = prefixText === null ? null : Number(prefixText);

  const v4 = parseIpv4(host);
  const v6 = v4 ? null : parseIpv6(host);
  if (!v4 && !v6) {
    errors.push(`"${shown}" is not a valid IPv4 or IPv6 address or CIDR range.`);
    return null;
  }
  const family = v4 ? 4 : 6;
  const bits = v4 ? 32 : 128;
  if (prefix !== null && prefix > bits) {
    errors.push(`"${shown}" has a prefix longer than ${bits}, the maximum for IPv${family}.`);
    return null;
  }

  const render = (parts: number[]) => (v4 ? parts.join('.') : formatIpv6(parts));
  const parts = (v4 ?? v6) as number[];
  if (prefix === null) return { family, text: render(parts), any: false };
  const network = maskParts(parts, prefix, v4 ? 8 : 16);
  const result = `${render(network)}/${prefix}`;
  if (network.some((part, index) => part !== parts[index])) {
    warnings.push(`${render(parts)}/${prefix} is not a network address. The rules use ${result}.`);
  }
  return { family, text: result, any: prefix === 0 };
}

const portText = (item: PortItem, rangeSeparator: string) => (item.from === item.to ? String(item.from) : `${item.from}${rangeSeparator}${item.to}`);
const portList = (items: PortItem[], rangeSeparator: string) => items.map(item => portText(item, rangeSeparator)).join(',');
const isSinglePort = (items: PortItem[]) => items.length === 1 && items[0].from === items[0].to;

/** Split a port list into groups that fit one multiport rule. */
function multiportGroups(items: PortItem[]): PortItem[][] {
  const groups: PortItem[][] = [];
  let current: PortItem[] = [];
  let weight = 0;
  for (const item of items) {
    const cost = item.from === item.to ? 1 : 2;
    if (weight + cost > MULTIPORT_LIMIT) {
      groups.push(current);
      current = [];
      weight = 0;
    }
    current.push(item);
    weight += cost;
  }
  if (current.length > 0) groups.push(current);
  return groups;
}

const join = (parts: Array<string | false | null | undefined>) => parts.filter(Boolean).join(' ');

function buildUfw(c: Context): FirewallOutput {
  // ufw refuses a comment that contains a single quote, however it is quoted.
  const comment = c.comment.replace(/'/g, '').trim();
  const head = join(['sudo ufw', c.action, c.inbound ? c.iface && `in on ${c.iface}` : join(['out', c.iface && `on ${c.iface}`])]);
  const line = (ports: string | null, proto: Proto | null) => {
    const match = c.inbound
      ? join([c.address ? `from ${c.address.text}` : !ports && 'from any', ports && `to any port ${ports}`])
      : join([`to ${c.address ? c.address.text : 'any'}`, ports && `port ${ports}`]);
    return join([head, match, proto && `proto ${proto}`, comment && `comment ${shQuote(comment)}`]);
  };

  const commands: string[] = [];
  if (c.ports.length === 0) {
    for (const proto of c.protos) commands.push(line(null, proto));
  } else if (c.protocol === 'both' && isSinglePort(c.ports)) {
    // Without proto, ufw applies a single port to TCP and UDP.
    commands.push(line(portList(c.ports, ':'), null));
  } else {
    // Port lists and ranges need a protocol.
    for (const proto of c.protos) {
      for (const group of multiportGroups(c.ports)) commands.push(line(portList(group, ':'), proto));
    }
  }

  const notes: string[] = [];
  if (comment !== c.comment) notes.push('ufw comments cannot contain a single quote, so it is removed here.');
  if (c.action !== 'allow') notes.push('ufw checks rules in order and the first match wins. To put this rule ahead of the existing ones, write "sudo ufw prepend" in place of "sudo ufw" (ufw 0.36 or later).');
  return { key: 'ufw', label: 'ufw', commands, persistence: 'ufw saves rules itself. They stay after a reboot once ufw is enabled (sudo ufw enable).', notes };
}

function buildFirewalld(c: Context): FirewallOutput {
  const output: FirewallOutput = {
    key: 'firewalld',
    label: 'firewalld',
    commands: [],
    persistence: '--permanent saves the rule. It takes effect after firewall-cmd --reload.',
    notes: [],
  };
  if (!c.inbound) {
    output.notes.push('Not generated: firewalld zones filter incoming traffic. Outbound filtering needs a policy or direct rules, which depend on your setup.');
    return output;
  }

  const protos = c.protos.filter((proto): proto is Proto => proto !== null);
  if (c.action === 'allow' && !c.address && c.ports.length > 0) {
    for (const proto of protos) {
      for (const item of c.ports) output.commands.push(`sudo firewall-cmd --permanent --add-port=${portText(item, '-')}/${proto}`);
    }
  } else {
    const verdict = c.action === 'allow' ? 'accept' : c.action === 'deny' ? 'drop' : 'reject';
    const elements: string[] = [];
    if (c.ports.length > 0) {
      for (const proto of protos) {
        for (const item of c.ports) elements.push(`port port="${portText(item, '-')}" protocol="${proto}"`);
      }
    } else if (protos.length > 0) {
      for (const proto of protos) elements.push(`protocol value="${proto}"`);
    } else if (c.address) {
      elements.push('');
    }
    if (elements.length === 0) {
      output.notes.push('Not generated: a firewalld rule needs a port, a protocol or a source address. To change what happens to all other traffic, set the zone target.');
      return output;
    }
    for (const element of elements) {
      const rule = join(['rule', c.address && `family="ipv${c.address.family}" source address="${c.address.text}"`, element, verdict]);
      output.commands.push(`sudo firewall-cmd --permanent --add-rich-rule=${shQuote(rule)}`);
    }
  }
  output.commands.push('sudo firewall-cmd --reload');

  output.notes.push('The rule goes to the default zone. Add --zone=NAME after --permanent to use another zone.');
  if (c.iface) output.notes.push(`firewalld has no interface match in a rule. Use the zone that ${c.iface} belongs to: firewall-cmd --get-zone-of-interface=${c.iface}`);
  return output;
}

function buildNftables(c: Context): FirewallOutput {
  const verdict = c.action === 'allow' ? 'accept' : c.action === 'deny' ? 'drop' : 'reject';
  const commands = c.protos.map(proto => {
    const ports = c.ports.length === 1 ? portText(c.ports[0], '-') : `{ ${c.ports.map(item => portText(item, '-')).join(', ')} }`;
    const rule = join([
      'add rule inet filter',
      c.inbound ? 'input' : 'output',
      c.iface && `${c.inbound ? 'iifname' : 'oifname'} "${c.iface}"`,
      c.address && `${c.address.family === 4 ? 'ip' : 'ip6'} ${c.inbound ? 'saddr' : 'daddr'} ${c.address.text}`,
      proto && (c.ports.length > 0 ? `${proto} dport ${ports}` : `meta l4proto ${proto}`),
      verdict,
      c.comment && `comment "${c.comment}"`,
    ]);
    // Quotes and braces must reach nft unchanged, so the rule is passed as one shell word.
    return `sudo nft ${/^[A-Za-z0-9_@+=:,./ -]+$/.test(rule) ? rule : shQuote(rule)}`;
  });

  const notes = ['Assumes an inet table named filter with input and output chains. Check yours with sudo nft list ruleset.', 'add rule appends to the end of the chain. Use insert rule to put it first.'];
  if (!c.inbound) notes.push('Outbound rules go in the output chain, and the address is matched as the destination (daddr).');
  return {
    key: 'nftables',
    label: 'nftables',
    commands,
    persistence: 'Save with: sudo nft list ruleset | sudo tee /etc/nftables.conf (and enable nftables.service so it loads at boot).',
    notes,
  };
}

function buildIptables(c: Context): FirewallOutput {
  const target = c.action === 'allow' ? 'ACCEPT' : c.action === 'deny' ? 'DROP' : 'REJECT';
  const families: Array<4 | 6> = c.address ? [c.address.family] : [4, 6];
  const portMatches = c.ports.length === 0
    ? ['']
    : c.ports.length === 1
      ? [`--dport ${portText(c.ports[0], ':')}`]
      : multiportGroups(c.ports).map(group => `-m multiport --dports ${portList(group, ':')}`);

  const commands: string[] = [];
  for (const family of families) {
    for (const proto of c.protos) {
      for (const portMatch of portMatches) {
        commands.push(join([
          'sudo',
          family === 4 ? 'iptables' : 'ip6tables',
          '-A',
          c.inbound ? 'INPUT' : 'OUTPUT',
          c.iface && `${c.inbound ? '-i' : '-o'} ${c.iface}`,
          proto && `-p ${proto}`,
          c.address && `${c.inbound ? '-s' : '-d'} ${c.address.text}`,
          portMatch,
          c.comment && `-m comment --comment ${shQuote(c.comment)}`,
          `-j ${target}`,
        ]));
      }
    }
  }

  const notes = ['-A appends after the existing rules, so an earlier rule may match first. Use -I in place of -A to insert at the top.'];
  if (!c.address) notes.push('iptables handles IPv4 and ip6tables handles IPv6, so there is one line for each.');
  return {
    key: 'iptables',
    label: 'iptables',
    commands,
    persistence: 'Save with sudo netfilter-persistent save (Debian, Ubuntu) or sudo service iptables save (RHEL family).',
    notes,
  };
}

function windowsName(c: Context, proto: Proto | null): string {
  if (c.comment && c.comment.toLowerCase() !== 'all') return c.protos.length > 1 && proto ? `${c.comment} (${proto.toUpperCase()})` : c.comment;
  const ports = portList(c.ports, '-');
  return join([
    c.action === 'allow' ? 'Allow' : 'Block',
    proto && proto.toUpperCase(),
    ports.length > 40 ? `${c.ports.length} port entries` : ports,
    c.inbound ? 'inbound' : 'outbound',
    c.address && `${c.inbound ? 'from' : 'to'} ${c.address.text}`,
  ]);
}

function windowsNotes(c: Context, interfaceHint: string): string[] {
  const notes = ['Block rules always win over allow rules on Windows, whatever the order.'];
  if (c.action === 'reject') notes.push('Windows Firewall has no reject action. The rule blocks without answering.');
  if (!c.inbound) notes.push('For outbound rules the port is the remote port.');
  if (c.iface) notes.push(`The interface ${c.iface} is left out: Windows uses its own adapter names. ${interfaceHint}`);
  return notes;
}

function buildPowerShell(c: Context): FirewallOutput {
  const commands = c.protos.map(proto => join([
    'New-NetFirewallRule',
    `-DisplayName ${psQuote(windowsName(c, proto))}`,
    `-Direction ${c.inbound ? 'Inbound' : 'Outbound'}`,
    `-Action ${c.action === 'allow' ? 'Allow' : 'Block'}`,
    proto && `-Protocol ${proto.toUpperCase()}`,
    c.ports.length > 0 && `${c.inbound ? '-LocalPort' : '-RemotePort'} ${portList(c.ports, '-')}`,
    c.address && `-RemoteAddress ${c.address.family === 6 ? psQuote(c.address.text) : c.address.text}`,
  ]));
  return {
    key: 'powershell',
    label: 'Windows Firewall (PowerShell)',
    commands,
    persistence: 'Run in PowerShell as administrator. The rule is saved at once and stays after a reboot.',
    notes: windowsNotes(c, 'Add -InterfaceAlias with the name from Get-NetAdapter.'),
  };
}

function buildNetsh(c: Context): FirewallOutput {
  const commands = c.protos.map(proto => join([
    'netsh advfirewall firewall add rule',
    `name="${windowsName(c, proto)}"`,
    `dir=${c.inbound ? 'in' : 'out'}`,
    `action=${c.action === 'allow' ? 'allow' : 'block'}`,
    proto && `protocol=${proto.toUpperCase()}`,
    c.ports.length > 0 && `${c.inbound ? 'localport' : 'remoteport'}=${portList(c.ports, '-')}`,
    c.address && `remoteip=${c.address.text}`,
  ]));
  return {
    key: 'netsh',
    label: 'Windows Firewall (netsh)',
    commands,
    persistence: 'Run in Command Prompt as administrator. The rule is saved at once and stays after a reboot.',
    notes: windowsNotes(c, 'netsh cannot match an adapter by name, so use the PowerShell form for that.'),
  };
}

export function buildFirewallRules(rule: FirewallRule): FirewallResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!['allow', 'deny', 'reject'].includes(rule.action)) errors.push('Action must be allow, deny or reject.');
  if (!['in', 'out'].includes(rule.direction)) errors.push('Direction must be in or out.');
  if (!['tcp', 'udp', 'both', 'any'].includes(rule.protocol)) errors.push('Protocol must be TCP, UDP, both or any.');

  const ports = parsePorts(rule.ports, errors);
  if (rule.protocol === 'any' && String(rule.ports ?? '').trim()) errors.push('Protocol "any" cannot be combined with ports. Choose TCP, UDP or both.');

  const address = parseAddress(rule.source, errors, warnings);

  const iface = String(rule.iface ?? '').trim();
  if (iface && !IFACE_PATTERN.test(iface)) errors.push('Interface must be 1 to 15 characters: letters, digits and _ . : @ -');

  const comment = String(rule.comment ?? '').trim();
  if (comment && !COMMENT_PATTERN.test(comment)) {
    errors.push('The comment can be up to 100 ASCII characters and cannot contain " \\ % | $ or a backtick. Some firewall tools cannot store those.');
  }

  if (errors.length > 0) return { outputs: [], errors, warnings: [] };

  const inbound = rule.direction === 'in';
  const anySource = !address || address.any;
  const tcp = rule.protocol !== 'udp';
  const covers = (port: number) => ports.length === 0 || ports.some(item => item.from <= port && port <= item.to);

  if (ports.length === 0) {
    const what = rule.protocol === 'any' ? 'all traffic' : rule.protocol === 'both' ? 'all TCP and UDP ports' : `all ${rule.protocol.toUpperCase()} ports`;
    warnings.push(`No ports are set, so the rule covers ${what}${address && !address.any ? ` ${inbound ? 'from' : 'to'} ${address.text}` : ''}.`);
  }
  if (inbound && anySource && tcp) {
    if (rule.action !== 'allow') {
      const hit = LOCKOUT_PORTS.filter(([port]) => covers(port));
      for (const [port, name] of hit) {
        warnings.push(`This blocks port ${port} from any source and can lock you out of ${name}. Allow your own address first.`);
      }
    } else if (ports.length > 0) {
      for (const [port, name, kind] of EXPOSED_PORTS) {
        if (covers(port)) warnings.push(`Port ${port} (${name}) is open to any source. That exposes ${kind} to the internet. Restrict the source address.`);
      }
      if (covers(23)) warnings.push('Port 23 (Telnet) is open to any source. Telnet sends passwords in clear text. Use SSH instead.');
    }
  }

  const protos: Array<Proto | null> = rule.protocol === 'any' ? [null] : rule.protocol === 'both' ? ['tcp', 'udp'] : [rule.protocol];
  const context: Context = { action: rule.action, inbound, protocol: rule.protocol, protos, ports, address, iface, comment };
  const outputs = [buildUfw(context), buildFirewalld(context), buildNftables(context), buildIptables(context), buildPowerShell(context), buildNetsh(context)];
  return { outputs, errors, warnings };
}
