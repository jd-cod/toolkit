'use client';

import { useRouter } from 'next/navigation';
import AsnSnapshotView from '@/components/AsnSnapshotView';
import DnsSnapshotView from '@/components/DnsSnapshotView';
import MyIpSnapshotView from '@/components/MyIpSnapshotView';
import WhoisSnapshotView from '@/components/WhoisSnapshotView';
import { normalizeAsnSnapshot } from '@/lib/asn';
import { buildRerunHref, normalizeSharedSnapshot } from '@/lib/dns';
import type { SnapshotTool } from '@/lib/share';
import { buildWhoisRerunHref, normalizeWhoisSnapshot } from '@/lib/whois';

interface SharedSnapshotProps {
  tool: SnapshotTool;
  snapshot: unknown;
  title?: string;
  code: string;
}

/**
 * Renders a shared snapshot with the read-only view of the tool that created
 * it. Each view carries the same download actions as its live page.
 */
export default function SharedSnapshot({ tool, snapshot, title, code }: SharedSnapshotProps) {
  const router = useRouter();

  switch (tool) {
    case 'dns': {
      const dns = normalizeSharedSnapshot(snapshot);
      return (
        <div style={{ maxWidth: 1100, margin: '0 auto' }}>
          <DnsSnapshotView snapshot={dns} mode="shared" title={title || 'Shared DNS Snapshot'} code={code} onRerun={() => router.push(buildRerunHref(dns))} />
        </div>
      );
    }
    case 'whois': {
      const whois = normalizeWhoisSnapshot(snapshot);
      return (
        <div style={{ maxWidth: 1100, margin: '0 auto' }}>
          <WhoisSnapshotView snapshot={whois} mode="shared" title={title || 'Shared WHOIS Snapshot'} code={code} onRerun={() => router.push(buildWhoisRerunHref(whois))} />
        </div>
      );
    }
    case 'myip':
      return (
        <div style={{ maxWidth: 900, margin: '0 auto' }}>
          <MyIpSnapshotView snapshot={snapshot} title={title} code={code} />
        </div>
      );
    case 'asn':
      return (
        <div style={{ maxWidth: 1100, margin: '0 auto' }}>
          <AsnSnapshotView
            snapshot={normalizeAsnSnapshot(snapshot)}
            mode="shared"
            title={title || 'Shared ASN Snapshot'}
            code={code}
            onRerun={(asn) => router.push(`/asn?asn=${encodeURIComponent(asn)}`)}
          />
        </div>
      );
    default:
      return (
        <div className="glass" style={{ maxWidth: 560, margin: '2rem auto', padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          This shared result cannot be displayed.
        </div>
      );
  }
}
