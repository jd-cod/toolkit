import Link from 'next/link';
import { Tool } from '@/lib/api';
import { toolMetadata } from '@/lib/tool-catalog';

export default function ToolCard({ tool }: { tool: Tool }) {
  const meta = toolMetadata(tool);

  return (
    <Link
      href={meta.route}
      prefetch={false}
      className="tool-card"
      id={`tool-card-${tool.tool_key}`}
      data-category={meta.category}
      style={{ '--tool-color': tool.color || 'var(--accent-primary)' } as React.CSSProperties}
    >
      <div className="signal-tool-card-top"><div className="tool-card-icon"><i className={`bi ${tool.icon || meta.icon}`} aria-hidden="true" /></div><i className="bi bi-arrow-up-right" aria-hidden="true" /></div>
      <h3 className="tool-card-title">{tool.label}</h3>
      <p className="tool-card-description">{tool.description}</p>
      <div className="signal-tool-card-meta"><span>{meta.category}</span><span>{meta.processing}</span></div>
    </Link>
  );
}
