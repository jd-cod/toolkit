import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { getSiteConfigServer } from '@/lib/site-config.server';
import { buildToolMetadata, buildStructuredData, serializeJsonLd } from '@/lib/seo';

export async function generateMetadata(): Promise<Metadata> {
  const config = await getSiteConfigServer();
  const tool = config?.tools.find(t => t.tool_key === 'dns');
  return buildToolMetadata('dns', tool, config?.settings);
}

export default async function DnsLayout({ children }: { children: ReactNode }) {
  const config = await getSiteConfigServer();
  const tool = config?.tools.find(t => t.tool_key === 'dns');
  const schema = buildStructuredData({ type: 'tool', toolKey: 'dns', toolOverride: tool });

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: serializeJsonLd(schema) }}
      />
      {children}
    </>
  );
}
