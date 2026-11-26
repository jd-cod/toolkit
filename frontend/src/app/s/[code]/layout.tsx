import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { buildPageMetadata } from '@/lib/seo';

export const metadata: Metadata = buildPageMetadata({
  path: '/s',
  title: 'Shared Report',
  description: 'Shared analysis snapshot.',
  noindex: true,
});

export default function SharedReportLayout({ children }: { children: ReactNode }) {
  return children;
}
