import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { buildPageMetadata } from '@/lib/seo';

export const metadata: Metadata = buildPageMetadata({
  path: '/login',
  title: 'Admin Login',
  description: 'Administrator authentication portal for SysAdmin Toolkit.',
});

export default function LoginLayout({ children }: { children: ReactNode }) {
  return children;
}
