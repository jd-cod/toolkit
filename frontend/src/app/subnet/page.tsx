'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { ToolEmptyState } from '@/components/ToolWorkspace';
import { exportToCSV } from '@/lib/csv-utils';
import { useClipboard } from '@/hooks/useClipboard';

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

function parseCIDR(input: string) {
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

export default function SubnetPage() {
  const { copy, isCopied } = useClipboard();
  const [input, setInput] = useState('192.168.1.0/24');
  const [awsMode, setAwsMode] = useState(false);
  const [result, setResult] = useState<ReturnType<typeof parseCIDR>>(null);
  const [error, setError] = useState('');

  function doCalculate() {
    if (!input.trim()) return;
    const parsed = parseCIDR(input);
    if (!parsed) { setError('Invalid CIDR. Use format: 10.0.0.0/24'); setResult(null); return; }
    setError(''); setResult(parsed);
  }

  const awsUsable = result ? Math.max(0, result.usableHosts - 5) : 0;
  const displayUsable = awsMode ? awsUsable : result?.usableHosts || 0;

  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading">
          <div style={{ width: 56, height: 56, borderRadius: 16, background: 'linear-gradient(135deg, #10b981, #10b981cc)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.6rem', color: '#fff', marginBottom: '1rem' }}><i className="bi bi-hdd-network-fill"></i></div>
          <h1 className="hero-title" style={{ fontSize: '2rem' }}>Subnet / CIDR Calculator</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Calculate network details, usable hosts, and AWS impact for CIDR blocks.</p>
        </div>

        <ToolWorkspace tool="subnet">
        <div className="glass" style={{ padding: '2rem', marginBottom: '2rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <input type="text" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && doCalculate()} placeholder="10.0.0.0/24 or 192.168.1.0 255.255.255.0" style={{ flex: 1, minWidth: 200, padding: '0.75rem 1rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: '0.95rem', fontFamily: 'var(--font-mono)' }} />
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              <input type="checkbox" checked={awsMode} onChange={e => setAwsMode(e.target.checked)} style={{ accentColor: 'var(--accent-amber)' }} /> AWS Mode
            </label>
            <button onClick={doCalculate} className="btn-primary">Calculate</button>
          </div>
        </div>

        {error && <div className="glass" style={{ padding: '1rem 1.5rem', borderColor: 'rgba(239,68,68,0.3)', color: 'var(--accent-red)', marginBottom: '1.5rem' }}>⚠️ {error}</div>}

        {!result && !error && <ToolEmptyState title="Size a subnet">Calculate a network to see its address boundaries, host capacity, and exportable details.</ToolEmptyState>}
        {result && (
          <>
            <div className="glass" style={{ padding: '1rem', marginBottom: '1.5rem', display: 'flex', gap: '0.75rem', justifyContent: 'center' }}>
              <button
                onClick={() => exportToCSV(result, `subnet-report-${result.cidr.replace(/\//g, '-')}`)}
                className="btn-secondary"
                style={{ padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                <i className="bi bi-download"></i> Export CSV
              </button>
              <button
                onClick={() => void copy(`CIDR: ${result.cidr}\nNetmask: ${result.maskStr}\nWildcard: ${result.wildcardStr}\nNetwork: ${result.networkStr}\nBroadcast: ${result.broadcastStr}\nUsable Range: ${result.firstHostStr} - ${result.lastHostStr}\nTotal Hosts: ${result.totalHosts}\nUsable Hosts: ${result.usableHosts}`, 'subnet')}
                className="btn-secondary"
                style={{ padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                <i className={isCopied('subnet') ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i> {isCopied('subnet') ? 'Copied Details!' : 'Copy Summary'}
              </button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
              <StatCard value={result.cidr} label="Network CIDR" color="var(--accent-cyan)" mono />
              <StatCard value={displayUsable.toLocaleString()} label={awsMode ? 'AWS Usable Hosts' : 'Usable Hosts'} color="var(--accent-primary)" />
              <StatCard value={result.totalHosts.toLocaleString()} label="Total Addresses" color="var(--accent-green)" />
              <StatCard value={`/${result.prefix}`} label="Prefix Length" color="var(--accent-amber)" />
            </div>

            {awsMode && (
              <div style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.15)', borderRadius: 10, padding: '0.75rem 1rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.625rem', fontSize: '0.82rem', color: 'var(--accent-amber)' }}>
                <i className="bi bi-cloud-fill"></i>
                <span>AWS reservations: Network, Gateway, DNS, Future, Broadcast (−5 IPs)</span>
              </div>
            )}

            <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
              <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
                <i className="bi bi-info-circle" style={{ marginRight: '0.5rem' }}></i>Subnet Details
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
                {[
                  ['Network Address', result.networkStr], ['Broadcast Address', result.broadcastStr],
                  ['First Usable Host', result.firstHostStr], ['Last Usable Host', result.lastHostStr],
                  ['Subnet Mask', result.maskStr], ['Wildcard Mask', result.wildcardStr],
                  ['Total Addresses', result.totalHosts.toLocaleString()], ['Usable Hosts', result.usableHosts.toLocaleString()],
                  ...(awsMode ? [['AWS Usable Hosts', awsUsable.toLocaleString()]] : []),
                  ['CIDR Notation', result.cidr], ['IP Class', result.ipClass], ['IP Type', result.ipType],
                ].map(([label, value]) => (
                  <tr key={label} style={{ borderBottom: '1px solid rgba(30,34,53,0.5)' }}>
                    <td style={{ padding: '0.625rem 1rem', color: 'var(--text-muted)', fontSize: '0.85rem', width: '40%' }}>{label}</td>
                    <td style={{ padding: '0.625rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.88rem', fontWeight: 500 }}>{value}</td>
                  </tr>
                ))}
              </tbody></table>
            </div>
          </>
        )}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}

function StatCard({ value, label, color, mono }: { value: string; label: string; color: string; mono?: boolean }) {
  return (
    <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderTop: `3px solid ${color}` }}>
      <div style={{ fontSize: mono ? '1rem' : '1.6rem', fontWeight: 800, color, fontFamily: mono ? 'var(--font-mono)' : 'var(--font-sans)' }}>{value}</div>
      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: '0.3rem' }}>{label}</div>
    </div>
  );
}
