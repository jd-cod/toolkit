'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useSiteConfig } from './WorkspaceShell';

export default function Footer({ footerText, copyrightText }: { footerText?: string; copyrightText?: string }) {
  const { config } = useSiteConfig();
  const pathname = usePathname();
  const text = footerText ?? config?.footer.footer_text;
  const copyright = copyrightText ?? config?.footer.copyright_text;
  const defaultTexts = [
    'SysAdmin Toolkit · GeoIP by MaxMind · All processing runs in your browser',
    'SysAdmin Toolkit · GeoIP by MaxMind · Local log analysis. Remote network lookups.',
  ];
  const localTool = ['/cron', '/subnet', '/chmod', '/password-generator'].includes(pathname);
  const lookupTool = ['/dns', '/ssl', '/whois', '/asn', '/abuse', '/myip'].includes(pathname);
  const defaultText = localTool
    ? 'SysAdmin Toolkit · This tool runs in your browser.'
    : pathname === '/nginx'
      ? 'SysAdmin Toolkit · GeoIP by MaxMind · Local log analysis. Remote sources and sharing use server services.'
      : lookupTool
        ? 'SysAdmin Toolkit · GeoIP by MaxMind · Network lookups use remote services.'
        : 'SysAdmin Toolkit · Network, security & browser-based tools · GeoIP by MaxMind';
  return (
    <footer className="footer" id="main-footer">
      <div><p>{text && !defaultTexts.includes(text) ? text : defaultText}</p>
      {copyright && <p>{copyright}</p>}</div>
      <nav aria-label="Footer links">{config?.menus?.footer?.filter(item => item.is_visible !== 0).map(item => (
        <Link key={item.id} href={item.url} prefetch={false} target={item.open_in_new_tab ? '_blank' : undefined} rel={item.open_in_new_tab ? 'noopener noreferrer' : undefined}>{item.label}</Link>
      ))}</nav>
    </footer>
  );
}
