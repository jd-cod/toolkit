import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { getSiteConfigServer } from '@/lib/site-config.server';
import { buildToolMetadata, buildStructuredData, serializeJsonLd } from '@/lib/seo';

export async function generateMetadata(): Promise<Metadata> {
  const config = await getSiteConfigServer();
  const tool = config?.tools.find(t => t.tool_key === 'subnet');
  return buildToolMetadata('subnet', tool, config?.settings);
}

export default async function SubnetLayout({ children }: { children: ReactNode }) {
  const config = await getSiteConfigServer();
  const tool = config?.tools.find(t => t.tool_key === 'subnet');
  const schema = buildStructuredData({ type: 'tool', toolKey: 'subnet', toolOverride: tool });

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
