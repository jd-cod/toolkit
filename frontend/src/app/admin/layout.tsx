import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { buildPageMetadata } from '@/lib/seo';

export const metadata: Metadata = buildPageMetadata({
  path: '/admin',
  title: 'Control Center',
  description: 'Administration dashboard for SysAdmin Toolkit.',
});

export default function AdminLayout({ children }: { children: ReactNode }) {
  return children;
}
