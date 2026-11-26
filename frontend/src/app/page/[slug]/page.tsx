import type { Metadata } from 'next';
import { cache } from 'react';
import { notFound } from 'next/navigation';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import { buildPageMetadata } from '@/lib/seo';
import type { ContentPage } from '@/components/admin/adminUtils';

const internalApiBase = (
  process.env.BACKEND_INTERNAL_URL ||
  process.env.BACKEND_API_URL ||
  'http://127.0.0.1:4000/api'
).replace(/\/+$/, '');

const getPageData = cache(async (slug: string): Promise<ContentPage | null | 'error'> => {
  try {
    const res = await fetch(`${internalApiBase}/site/page/${encodeURIComponent(slug)}`, {
      cache: 'no-store',
      headers: { Accept: 'application/json' },
    });
    if (res.status === 404) return null;
    if (!res.ok) return 'error';
    return (await res.json()) as ContentPage;
  } catch (err: unknown) {
    if (typeof err === 'object' && err !== null && 'digest' in err) {
      throw err;
    }
    console.error(`[CMSPage] Error fetching slug "${slug}":`, err);
    return 'error';
  }
});

type Props = {
  params: Promise<{ slug: string }>;
};

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const page = await getPageData(slug);

  if (page === null) {
    return {
      title: 'Page Not Found | SysAdmin Toolkit',
      robots: { index: false, follow: false },
    };
  }

  if (page === 'error') {
    return {
      title: 'Service Temporarily Unavailable | SysAdmin Toolkit',
      robots: { index: false, follow: false },
    };
  }

  return buildPageMetadata({
    path: `/page/${slug}`,
    title: page.meta_title || page.title,
    description: page.meta_description,
    noindex: Boolean(page.seo_noindex),
  });
}

export default async function CMSPage({ params }: Props) {
  const { slug } = await params;
  const page = await getPageData(slug);

  if (page === null) {
    notFound();
  }

  if (page === 'error') {
    return (
      <>
        <Navbar />
        <main className="main-content">
          <div style={{ textAlign: 'center', padding: '4rem 0' }}>
            <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>⚠️</div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.5rem' }}>Service Temporarily Unavailable</h1>
            <p style={{ color: 'var(--text-muted)' }}>Unable to load this page right now. Please check back shortly.</p>
          </div>
        </main>
        <Footer />
      </>
    );
  }

  return (
    <>
      <Navbar />
      <main className="main-content">
        <article className="glass" style={{ padding: '3rem', maxWidth: 800, margin: '0 auto' }}>
          <h1 style={{ fontSize: '2rem', fontWeight: 800, marginBottom: '1.5rem', letterSpacing: '-0.03em' }}>{page.title}</h1>
          <div
            style={{ color: 'var(--text-secondary)', lineHeight: 1.8, fontSize: '0.95rem' }}
            dangerouslySetInnerHTML={{ __html: page.content }}
          />
        </article>
      </main>
      <Footer />
    </>
  );
}
