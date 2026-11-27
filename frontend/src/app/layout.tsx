import type { Metadata } from 'next';
import './globals.css';
import './signal.css';
import './signal-nginx.css';
import './tool-kit.css';
import localFont from 'next/font/local';
import { ThemeProvider } from '@/components/ThemeProvider';
import WorkspaceShell from '@/components/WorkspaceShell';
import { getSiteConfigServer } from '@/lib/site-config.server';
import { SITE_URL, DEFAULT_TITLE, DEFAULT_DESCRIPTION, BRAND_NAME } from '@/lib/seo';

const interfaceFont = localFont({
  src: [
    { path: '../../public/fonts/dm-sans-400.ttf', weight: '400' },
    { path: '../../public/fonts/dm-sans-600.ttf', weight: '600' },
    { path: '../../public/fonts/dm-sans-700.ttf', weight: '700' },
  ],
  variable: '--font-signal',
  display: 'swap',
});
const headingFont = localFont({ src: '../../public/fonts/manrope-700.ttf', weight: '700', variable: '--font-signal-heading', display: 'swap' });

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: DEFAULT_TITLE,
  description: DEFAULT_DESCRIPTION,
  alternates: {
    canonical: '/',
  },
  robots: {
    index: true,
    follow: true,
  },
  icons: {
    icon: '/favicon.ico',
  },
  openGraph: {
    title: DEFAULT_TITLE,
    description: DEFAULT_DESCRIPTION,
    url: SITE_URL,
    siteName: BRAND_NAME,
    type: 'website',
    images: [
      {
        url: `${SITE_URL}/og-image.png`,
        width: 1200,
        height: 630,
        alt: BRAND_NAME,
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: DEFAULT_TITLE,
    description: DEFAULT_DESCRIPTION,
    images: [`${SITE_URL}/og-image.png`],
  },
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const initialConfig = await getSiteConfigServer();

  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head>
        <link
          rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"
        />
      </head>
      <body className={`${interfaceFont.variable} ${headingFont.variable}`} suppressHydrationWarning>
        <ThemeProvider>
          <WorkspaceShell initialConfig={initialConfig}>{children}</WorkspaceShell>
        </ThemeProvider>
      </body>
    </html>
  );
}
