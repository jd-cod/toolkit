'use client';

import ResultActions, { ResultActionButton } from '@/components/share/ResultActions';
import { useClipboard } from '@/hooks/useClipboard';
import { snapshotShare } from '@/lib/api';
import { fileSlug } from '@/lib/download';
import {
  awsUsableHosts,
  buildSubnetReportHtml,
  buildSubnetSummary,
  subnetDetailRows,
  type SubnetResult,
  type SubnetSnapshot,
} from '@/lib/subnet';

interface SubnetResultViewProps {
  result: SubnetResult;
  awsMode: boolean;
  mode: 'live' | 'shared';
  /** When the calculation was made; shared links pass the stored time. */
  checkedAt?: string;
}

/** Subnet calculation results, used by the live calculator and by shared links. */
export default function SubnetResultView({ result, awsMode, mode, checkedAt }: SubnetResultViewProps) {
  const { copy, isCopied } = useClipboard();
  const displayUsable = awsMode ? awsUsableHosts(result) : result.usableHosts;
  const filename = `subnet-report-${fileSlug(result.cidr)}`;
  const snapshot = (): SubnetSnapshot => ({ cidr: result.cidr, aws_mode: awsMode, checked_at_utc: checkedAt || new Date().toISOString() });

  return (
    <>
      <div style={{ marginBottom: '1.5rem' }}>
        <ResultActions
          className="signal-actions-end"
          share={mode === 'live' ? {
            heading: 'Share Subnet Report',
            title: `Subnet ${result.cidr}`,
            create: snapshotShare('subnet', result.cidr, snapshot),
          } : undefined}
          html={{ filename, build: () => buildSubnetReportHtml(result, awsMode, checkedAt || new Date().toISOString()) }}
          csv={{ filename, rows: () => result }}
        >
          <ResultActionButton
            icon={isCopied('subnet') ? 'check-lg' : 'clipboard'}
            onClick={() => void copy(buildSubnetSummary(result, awsMode), 'subnet')}
          >
            {isCopied('subnet') ? 'Copied' : 'Copy Summary'}
          </ResultActionButton>
        </ResultActions>
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
          {subnetDetailRows(result, awsMode).map(([label, value]) => (
            <tr key={label} style={{ borderBottom: '1px solid rgba(30,34,53,0.5)' }}>
              <td style={{ padding: '0.625rem 1rem', color: 'var(--text-muted)', fontSize: '0.85rem', width: '40%' }}>{label}</td>
              <td style={{ padding: '0.625rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.88rem', fontWeight: 500 }}>{value}</td>
            </tr>
          ))}
        </tbody></table>
      </div>
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
