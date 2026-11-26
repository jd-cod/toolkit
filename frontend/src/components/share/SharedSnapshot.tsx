'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import type { ReactNode } from 'react';
import AsnSnapshotView from '@/components/AsnSnapshotView';
import ChmodResultView from '@/components/ChmodResultView';
import CronResultView from '@/components/CronResultView';
import DnsSnapshotView from '@/components/DnsSnapshotView';
import IpInfoResultView from '@/components/IpInfoResultView';
import MyIpSnapshotView from '@/components/MyIpSnapshotView';
import SslResultView from '@/components/SslResultView';
import SubnetResultView from '@/components/SubnetResultView';
import WhoisSnapshotView from '@/components/WhoisSnapshotView';
import { normalizeAsnSnapshot } from '@/lib/asn';
import { normalizeChmodSnapshot } from '@/lib/chmod';
import { normalizeCronSnapshot } from '@/lib/cron';
import { buildRerunHref, normalizeSharedSnapshot } from '@/lib/dns';
import { normalizeIpInfoSnapshot } from '@/lib/ipinfo';
import type { SnapshotTool } from '@/lib/share';
import { buildSslRerunHref, normalizeSslSnapshot } from '@/lib/ssl';
import { normalizeSubnetSnapshot, parseCIDR } from '@/lib/subnet';
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
    case 'ssl': {
      const ssl = normalizeSslSnapshot(snapshot);
      return (
        <SharedFrame title={title} code={code} liveHref={buildSslRerunHref(ssl)} liveLabel="Check Again">
          <SslResultView result={ssl} mode="shared" />
        </SharedFrame>
      );
    }
    case 'abuse':
      return (
        <SharedFrame title={title} code={code} liveHref="/abuse" liveLabel="New IP Lookup" wide>
          <IpInfoResultView snapshot={normalizeIpInfoSnapshot(snapshot)} mode="shared" />
        </SharedFrame>
      );
    case 'subnet': {
      const subnet = normalizeSubnetSnapshot(snapshot);
      const result = parseCIDR(subnet.cidr);
      return (
        <SharedFrame title={title} code={code} liveHref="/subnet" liveLabel="Open Calculator">
          {result
            ? <SubnetResultView result={result} awsMode={subnet.aws_mode} mode="shared" checkedAt={subnet.checked_at_utc} />
            : <Unreadable />}
        </SharedFrame>
      );
    }
    case 'cron': {
      const cron = normalizeCronSnapshot(snapshot);
      return (
        <SharedFrame title={title} code={code} liveHref="/cron" liveLabel="Open Builder">
          {cron.expression ? <CronResultView expr={cron.expression} mode="shared" /> : <Unreadable />}
        </SharedFrame>
      );
    }
    case 'chmod': {
      const chmod = normalizeChmodSnapshot(snapshot);
      return (
        <SharedFrame title={title} code={code} liveHref="/chmod" liveLabel="Open Calculator">
          {chmod.octal ? <ChmodResultView octal={chmod.octal} mode="shared" /> : <Unreadable />}
        </SharedFrame>
      );
    }
    default:
      return <Unreadable />;
  }
}

function Unreadable() {
  return (
    <div className="glass" style={{ maxWidth: 560, margin: '2rem auto', padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
      This shared result cannot be displayed.
    </div>
  );
}

interface SharedFrameProps {
  title?: string;
  code: string;
  liveHref: string;
  liveLabel: string;
  wide?: boolean;
  children: ReactNode;
}

/** Read-only notice and a link back to the live tool, for views that have no banner of their own. */
function SharedFrame({ title, code, liveHref, liveLabel, wide, children }: SharedFrameProps) {
  return (
    <div style={{ maxWidth: wide ? 1400 : 1100, margin: '0 auto' }}>
      <div className="signal-shared-banner">
        <i className="bi bi-share-fill" aria-hidden="true" />
        <span>You are viewing <strong>{title || 'a shared result'}</strong> — read-only snapshot.</span>
        <code>/s/{code}</code>
        <Link href={liveHref}><i className="bi bi-arrow-up-right-circle" aria-hidden="true" />{liveLabel}</Link>
      </div>
      {children}
    </div>
  );
}
