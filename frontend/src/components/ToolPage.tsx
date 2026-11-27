import type { ReactNode } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { type GuidedTool } from '@/components/ToolWorkspace';

/**
 * Page frame shared by the tools added in the 2026-11 tools pack: navbar,
 * heading, the workspace with its side guide, and footer. The guide text for
 * `tool` lives in ToolWorkspace's GUIDES.
 */
export default function ToolPage({
  tool,
  title,
  icon,
  lead,
  wide = false,
  children,
}: {
  tool: GuidedTool;
  title: string;
  icon: string;
  lead: string;
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading tool-hero-compact">
          <div className="tool-hero-icon"><i className={`bi ${icon}`} aria-hidden="true" /></div>
          <h1 className="hero-title">{title}</h1>
          <p>{lead}</p>
        </div>
        <ToolWorkspace tool={tool} wide={wide}>{children}</ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}
