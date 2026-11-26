import type { Metadata } from 'next';
import { getSiteConfigServer } from '@/lib/site-config.server';
import { buildToolMetadata, buildPageMetadata, buildStructuredData, serializeJsonLd } from '@/lib/seo';
import NginxClient from './NginxClient';

type Props = {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
};

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  const sp = await searchParams;
  const isSensitive = Boolean(sp?.session || sp?.ingest);
  if (isSensitive) {
    return buildPageMetadata({ path: '/nginx', isSensitiveQuery: true });
  }
  const config = await getSiteConfigServer();
  const tool = config?.tools.find(t => t.tool_key === 'nginx');
  return buildToolMetadata('nginx', tool, config?.settings);
}

export default async function NginxPage() {
  const config = await getSiteConfigServer();
  const tool = config?.tools.find(t => t.tool_key === 'nginx');
  const schema = buildStructuredData({ type: 'tool', toolKey: 'nginx', toolOverride: tool });

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: serializeJsonLd(schema) }}
      />
      <NginxClient />
    </>
  );
}
