/**
 * ASN & IP Math Utilities
 * CIDR parsing, range calculation, aggregation/optimization, and firewall rule generation.
 */

export function ipv4ToLong(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
}

export function longToIpv4(long) {
  return [
    (long >>> 24) & 255,
    (long >>> 16) & 255,
    (long >>> 8) & 255,
    long & 255,
  ].join('.');
}

export function parseIpv4Cidr(cidr) {
  if (!cidr || typeof cidr !== 'string') return null;
  const [ip, maskStr] = cidr.trim().split('/');
  const mask = parseInt(maskStr, 10);
  if (isNaN(mask) || mask < 0 || mask > 32) return null;

  const ipLong = ipv4ToLong(ip);
  if (ipLong === null) return null;

  const netmaskLong = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
  const wildcardLong = (~netmaskLong) >>> 0;
  const startLong = (ipLong & netmaskLong) >>> 0;
  const endLong = (startLong | wildcardLong) >>> 0;
  const totalIps = Math.pow(2, 32 - mask);

  return {
    prefix: `${longToIpv4(startLong)}/${mask}`,
    ip_version: 'ipv4',
    mask,
    netmask: longToIpv4(netmaskLong),
    wildcard: longToIpv4(wildcardLong),
    first_ip: longToIpv4(startLong),
    last_ip: longToIpv4(endLong),
    start_long: startLong,
    end_long: endLong,
    total_ips: totalIps,
  };
}

export function parseIpv6Cidr(cidr) {
  if (!cidr || typeof cidr !== 'string') return null;
  const [ip, maskStr] = cidr.trim().split('/');
  const mask = parseInt(maskStr, 10);
  if (isNaN(mask) || mask < 0 || mask > 128) return null;

  return {
    prefix: cidr.trim(),
    ip_version: 'ipv6',
    mask,
    netmask: `/${mask}`,
    wildcard: '',
    first_ip: ip,
    last_ip: '',
    start_long: null,
    end_long: null,
    total_ips: mask <= 64 ? Math.pow(2, 64 - mask) : 1,
  };
}

/**
 * Aggregates/merges adjacent and overlapping IPv4 CIDR blocks.
 */
export function aggregateIpv4Cidrs(cidrList) {
  const parsed = [];
  for (const c of cidrList) {
    const p = typeof c === 'string' ? parseIpv4Cidr(c) : (c.start_long != null ? c : parseIpv4Cidr(c.prefix));
    if (p && p.ip_version === 'ipv4') {
      parsed.push(p);
    }
  }

  if (parsed.length === 0) {
    return {
      original_count: 0,
      aggregated_count: 0,
      saved_rules: 0,
      reduction_percent: 0,
      prefixes: [],
    };
  }

  // Sort by start_long ascending, then mask ascending (larger block first)
  parsed.sort((a, b) => a.start_long - b.start_long || a.mask - b.mask);

  // Step 1: Remove completely contained / redundant blocks
  let nonOverlapping = [];
  for (const block of parsed) {
    if (nonOverlapping.length === 0) {
      nonOverlapping.push(block);
      continue;
    }
    const prev = nonOverlapping[nonOverlapping.length - 1];
    // Check if current is fully inside prev
    if (block.start_long >= prev.start_long && block.end_long <= prev.end_long) {
      continue; // Redundant!
    }
    nonOverlapping.push(block);
  }

  // Step 2: Iteratively merge adjacent buddy blocks of equal mask size
  let merged = true;
  let currentList = nonOverlapping;

  while (merged) {
    merged = false;
    const nextList = [];
    let i = 0;

    while (i < currentList.length) {
      const a = currentList[i];
      if (i + 1 < currentList.length) {
        const b = currentList[i + 1];
        if (a.mask === b.mask && a.mask > 0) {
          const parentMask = a.mask - 1;
          const parentNetmaskLong = parentMask === 0 ? 0 : (~0 << (32 - parentMask)) >>> 0;
          const aParentStart = (a.start_long & parentNetmaskLong) >>> 0;
          const bParentStart = (b.start_long & parentNetmaskLong) >>> 0;

          if (aParentStart === bParentStart && a.end_long + 1 === b.start_long) {
            // Can merge into parent block!
            const parentCidr = parseIpv4Cidr(`${longToIpv4(aParentStart)}/${parentMask}`);
            nextList.push(parentCidr);
            i += 2;
            merged = true;
            continue;
          }
        }
      }
      nextList.push(a);
      i += 1;
    }
    currentList = nextList;
  }

  const origCount = parsed.length;
  const aggCount = currentList.length;
  const saved = Math.max(0, origCount - aggCount);
  const reduction = origCount > 0 ? Math.round((saved / origCount) * 100) : 0;

  return {
    original_count: origCount,
    aggregated_count: aggCount,
    saved_rules: saved,
    reduction_percent: reduction,
    prefixes: currentList,
  };
}

/**
 * Checks if a candidate IP string is contained in any of the provided prefixes.
 */
export function matchIpInPrefixes(candidateIp, prefixes) {
  if (!candidateIp || typeof candidateIp !== 'string') return null;
  const cleanIp = candidateIp.trim();

  const isV4 = !cleanIp.includes(':');
  if (isV4) {
    const targetLong = ipv4ToLong(cleanIp);
    if (targetLong === null) return { valid: false, error: 'Invalid IPv4 address.' };

    for (const p of prefixes) {
      const parsed = p.start_long != null ? p : parseIpv4Cidr(p.prefix || p);
      if (parsed && targetLong >= parsed.start_long && targetLong <= parsed.end_long) {
        return {
          matched: true,
          ip: cleanIp,
          ip_version: 'ipv4',
          prefix: parsed.prefix,
          first_ip: parsed.first_ip,
          last_ip: parsed.last_ip,
          netmask: parsed.netmask,
          total_ips: parsed.total_ips,
        };
      }
    }
    return { matched: false, ip: cleanIp, ip_version: 'ipv4' };
  } else {
    // IPv6 prefix match check (basic string prefix check or full match)
    for (const p of prefixes) {
      const prefixStr = (p.prefix || p).toString().trim();
      const baseV6 = prefixStr.split('/')[0].toLowerCase();
      if (cleanIp.toLowerCase().startsWith(baseV6)) {
        return {
          matched: true,
          ip: cleanIp,
          ip_version: 'ipv6',
          prefix: prefixStr,
        };
      }
    }
    return { matched: false, ip: cleanIp, ip_version: 'ipv6' };
  }
}

/**
 * Computes subnet size distribution.
 */
export function calculateSubnetDistribution(ipv4Prefixes, ipv6Prefixes) {
  const v4Distribution = {};
  let totalIpv4Addresses = 0;

  for (const p of ipv4Prefixes) {
    const mask = p.mask ?? (p.prefix ? parseInt(p.prefix.split('/')[1], 10) : null);
    if (mask != null && !isNaN(mask)) {
      const label = `/${mask}`;
      v4Distribution[label] = (v4Distribution[label] || 0) + 1;
      totalIpv4Addresses += Math.pow(2, 32 - mask);
    }
  }

  const v6Distribution = {};
  for (const p of ipv6Prefixes) {
    const mask = p.mask ?? (p.prefix ? parseInt(p.prefix.split('/')[1], 10) : null);
    if (mask != null && !isNaN(mask)) {
      const label = `/${mask}`;
      v6Distribution[label] = (v6Distribution[label] || 0) + 1;
    }
  }

  return {
    v4_distribution: v4Distribution,
    v6_distribution: v6Distribution,
    total_ipv4_addresses: totalIpv4Addresses,
  };
}

/**
 * Generates firewall / security configuration rules for multiple platforms.
 */
export function generateFirewallRules({
  format = 'nginx',
  action = 'deny',
  asn = '',
  orgName = '',
  prefixes = [],
}) {
  const isBlock = action === 'deny' || action === 'drop' || action === 'block';
  const lines = [];
  const headerComment = `# AS${asn} (${orgName || 'ASN'}) - Generated ${new Date().toISOString().slice(0, 10)} - Total: ${prefixes.length} prefixes`;

  switch (format) {
    case 'nginx':
      lines.push(headerComment);
      for (const p of prefixes) {
        lines.push(`${isBlock ? 'deny' : 'allow'} ${p.prefix};`);
      }
      break;

    case 'apache':
      lines.push(headerComment);
      lines.push('<RequireAll>');
      for (const p of prefixes) {
        lines.push(`  ${isBlock ? 'Require not ip' : 'Require ip'} ${p.prefix}`);
      }
      lines.push('</RequireAll>');
      break;

    case 'iptables':
      lines.push(headerComment);
      for (const p of prefixes) {
        if (!p.prefix.includes(':')) {
          lines.push(`iptables -A INPUT -s ${p.prefix} -j ${isBlock ? 'DROP' : 'ACCEPT'}`);
        } else {
          lines.push(`ip6tables -A INPUT -s ${p.prefix} -j ${isBlock ? 'DROP' : 'ACCEPT'}`);
        }
      }
      break;

    case 'nftables':
      lines.push(headerComment);
      lines.push(`table inet filter {`);
      lines.push(`  set as${asn}_rules {`);
      lines.push(`    type ipv4_addr; flags interval;`);
      lines.push(`    elements = {`);
      for (const p of prefixes) {
        if (!p.prefix.includes(':')) {
          lines.push(`      ${p.prefix},`);
        }
      }
      lines.push(`    }`);
      lines.push(`  }`);
      lines.push(`  chain input {`);
      lines.push(`    ip saddr @as${asn}_rules ${isBlock ? 'drop' : 'accept'}`);
      lines.push(`  }`);
      lines.push(`}`);
      break;

    case 'ufw':
      lines.push(headerComment);
      for (const p of prefixes) {
        lines.push(`ufw ${isBlock ? 'deny from' : 'allow from'} ${p.prefix}`);
      }
      break;

    case 'cisco_acl':
      lines.push(headerComment);
      for (const p of prefixes) {
        if (!p.prefix.includes(':')) {
          const parsed = p.wildcard ? p : parseIpv4Cidr(p.prefix);
          if (parsed) {
            lines.push(`access-list 100 ${isBlock ? 'deny' : 'permit'} ip ${parsed.first_ip} ${parsed.wildcard} any`);
          }
        }
      }
      break;

    case 'mikrotik':
      lines.push(headerComment);
      const listName = isBlock ? `BLOCKED_AS${asn}` : `ALLOWED_AS${asn}`;
      for (const p of prefixes) {
        lines.push(`/ip firewall address-list add list=${listName} address=${p.prefix} comment="AS${asn} ${orgName}"`);
      }
      break;

    case 'ipset':
      lines.push(headerComment);
      const ipsetName = `as${asn}_${isBlock ? 'block' : 'allow'}`;
      lines.push(`ipset create ${ipsetName} hash:net family inet`);
      for (const p of prefixes) {
        if (!p.prefix.includes(':')) {
          lines.push(`ipset add ${ipsetName} ${p.prefix}`);
        }
      }
      lines.push(`# To apply: iptables -I INPUT -m set --match-set ${ipsetName} src -j ${isBlock ? 'DROP' : 'ACCEPT'}`);
      break;

    case 'aws_sg':
      const awsRules = prefixes.map(p => ({
        CidrIp: p.prefix.includes(':') ? undefined : p.prefix,
        CidrIpv6: p.prefix.includes(':') ? p.prefix : undefined,
        Description: `AS${asn} ${orgName || ''}`.trim(),
      }));
      return JSON.stringify(awsRules, null, 2);

    case 'pfsense':
      lines.push(headerComment);
      for (const p of prefixes) {
        lines.push(p.prefix);
      }
      break;

    case 'csv':
      lines.push('Prefix,IP_Version,Start_IP,End_IP,Netmask,Wildcard_Mask,Total_IPs');
      for (const p of prefixes) {
        const isV6 = p.prefix.includes(':');
        const parsed = isV6 ? parseIpv6Cidr(p.prefix) : (p.first_ip ? p : parseIpv4Cidr(p.prefix));
        if (parsed) {
          lines.push(`${parsed.prefix},${parsed.ip_version},${parsed.first_ip || ''},${parsed.last_ip || ''},${parsed.netmask || ''},${parsed.wildcard || ''},${parsed.total_ips || ''}`);
        }
      }
      break;

    case 'json':
      return JSON.stringify(prefixes, null, 2);

    case 'plain_text':
    default:
      for (const p of prefixes) {
        lines.push(p.prefix);
      }
      break;
  }

  return lines.join('\n');
}
