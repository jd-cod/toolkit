import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { getSiteConfigServer } from '@/lib/site-config.server';
import { buildToolMetadata, buildStructuredData } from '@/lib/seo';

/**
 * Builds the `generateMetadata` and default layout exports for a tool route,
 * so a tool's layout.tsx is two lines:
 *
 *   const { generateMetadata, Layout } = createToolLayout('rsync');
 *   export { generateMetadata }; export default Layout;
 */
export function createToolLayout(toolKey: string) {
  async function generateMetadata(): Promise<Metadata> {
    const config = await getSiteConfigServer();
    const tool = config?.tools.find(t => t.tool_key === toolKey);
    return buildToolMetadata(toolKey, tool, config?.settings);
  }

  async function Layout({ children }: { children: ReactNode }) {
    const config = await getSiteConfigServer();
    const tool = config?.tools.find(t => t.tool_key === toolKey);
    const schema = buildStructuredData({ type: 'tool', toolKey, toolOverride: tool });
    return (
      <>
        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />
        {children}
      </>
    );
  }

  return { generateMetadata, Layout };
}
