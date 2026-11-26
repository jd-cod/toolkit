'use client';
import { useState, useEffect, useCallback, lazy, Suspense } from 'react';
import { adminApi, formatTime, errorMessage, type ContentPage } from './adminUtils';
import { useToast } from './AdminToast';
import AdminModal from './AdminModal';

const RichEditor = lazy(() => import('./RichEditor'));

export default function PagesSection() {
  const { toast } = useToast();
  const [pages, setPages] = useState<ContentPage[]>([]);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({ id: '', title: '', slug: '', content: '', is_published: true, meta_title: '', meta_description: '', seo_noindex: false });
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<ContentPage | null>(null);

  const load = useCallback(() => adminApi<ContentPage[]>('/pages').then(setPages).catch(e => toast('Failed to load pages: ' + errorMessage(e), 'error')), [toast]);
  useEffect(() => { void load(); }, [load]);

  const updateForm = <K extends keyof typeof form>(k: K, v: typeof form[K]) => setForm(p => ({ ...p, [k]: v }));

  const autoSlug = (title: string) => title.toLowerCase().replace(/[^a-z0-9\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-');

  function newPage() {
    setForm({ id: '', title: '', slug: '', content: '', is_published: true, meta_title: '', meta_description: '', seo_noindex: false });
    setEditing(true);
  }

  async function editPage(id: number) {
    try {
      const page = await adminApi<ContentPage>(`/pages/${id}`);
      setForm({ id: String(page.id), title: page.title, slug: page.slug, content: page.content || '', is_published: !!page.is_published, meta_title: page.meta_title || '', meta_description: page.meta_description || '', seo_noindex: !!page.seo_noindex });
      setEditing(true);
    } catch (e) { toast('Failed to load page: ' + errorMessage(e), 'error'); }
  }

  async function savePage() {
    if (!form.title || !form.slug) { toast('Title and slug are required', 'error'); return; }
    setSaving(true);
    try {
      const body = { title: form.title, slug: form.slug, content: form.content, is_published: form.is_published, meta_title: form.meta_title, meta_description: form.meta_description, seo_noindex: form.seo_noindex };
      if (form.id) {
        await adminApi(`/pages/${form.id}`, { method: 'PUT', body });
        toast('Page updated successfully!');
      } else {
        await adminApi('/pages', { method: 'POST', body });
        toast('Page created successfully!');
      }
      setEditing(false);
      load();
    } catch (e) { toast('Failed to save: ' + errorMessage(e), 'error'); }
    setSaving(false);
  }

  async function confirmDelete() {
    if (!deleting) return;
    try {
      await adminApi(`/pages/${deleting.id}`, { method: 'DELETE' });
      toast('Page deleted!');
      setDeleting(null);
      load();
    } catch (e) { toast('Failed to delete: ' + errorMessage(e), 'error'); }
  }

  if (editing) {
    return (
      <>
        <div className="d-flex align-center gap-2 mb-4">
          <button className="btn btn-sm btn-admin-outline" onClick={() => setEditing(false)}>
            <i className="bi bi-arrow-left" /> Back to Pages
          </button>
          <div style={{ flex: 1 }} />
          <button className="btn btn-sm btn-admin-primary" onClick={savePage} disabled={saving}>
            <i className={`bi ${saving ? 'bi-hourglass-split' : 'bi-check-lg'}`} /> {saving ? 'Saving...' : 'Save Page'}
          </button>
        </div>
        <div className="admin-card">
          <div className="admin-card-body">
            <div className="form-group">
              <label className="form-label">Page Title</label>
              <input className="form-input" value={form.title} onChange={e => { updateForm('title', e.target.value); if (!form.id) updateForm('slug', autoSlug(e.target.value)); }} placeholder="e.g. About Us" style={{ fontSize: '1.1rem', fontWeight: 600 }} />
            </div>
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">URL Slug</label>
                <input className="form-input" value={form.slug} onChange={e => updateForm('slug', e.target.value)} placeholder="e.g. about-us" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }} />
                <p className="form-hint">The page will be accessible at /page/your-slug</p>
              </div>
              <div className="form-group">
                <label className="form-label">Status</label>
                <select className="form-select" value={form.is_published ? '1' : '0'} onChange={e => updateForm('is_published', e.target.value === '1')}>
                  <option value="1">Published</option>
                  <option value="0">Draft</option>
                </select>
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">Content</label>
              <Suspense fallback={<div className="skeleton" style={{ height: 300 }} />}>
                <RichEditor content={form.content} onChange={html => updateForm('content', html)} placeholder="Start writing your page content..." />
              </Suspense>
            </div>
            <hr className="form-divider" />
            <h4 style={{ marginBottom: 16, fontSize: '0.95rem', fontWeight: 600 }}>SEO Settings</h4>
            <div className="form-group">
              <label className="form-label">Meta Title</label>
              <input className="form-input" value={form.meta_title} onChange={e => updateForm('meta_title', e.target.value)} placeholder="Custom title for search engines (optional)" />
            </div>
            <div className="form-group">
              <label className="form-label">Meta Description</label>
              <textarea className="form-textarea" value={form.meta_description} onChange={e => updateForm('meta_description', e.target.value)} rows={2} placeholder="Custom description for search engines (optional)" />
            </div>
            <div className="form-group">
              <label className="toggle-switch-label d-flex align-center gap-2" style={{ cursor: 'pointer', marginTop: '0.5rem' }}>
                <input
                  type="checkbox"
                  checked={form.seo_noindex}
                  onChange={e => updateForm('seo_noindex', e.target.checked)}
                />
                <span style={{ fontSize: '0.85rem' }}>Exclude from search engines (<code style={{ fontSize: '0.8rem' }}>noindex</code>)</span>
              </label>
              <p className="form-hint">When checked, this page will not be included in the sitemap and crawlers will be instructed not to index it.</p>
            </div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="d-flex align-center justify-between mb-4">
        <div />
        <button className="btn btn-sm btn-admin-primary" onClick={newPage}><i className="bi bi-plus-lg" /> New Page</button>
      </div>
      <div className="admin-card">
        <div className="admin-card-body" style={{ padding: 0 }}>
          <table className="admin-table">
            <thead><tr><th>Title</th><th>Slug</th><th>Status</th><th>Updated</th><th style={{ width: 120 }}>Actions</th></tr></thead>
            <tbody>
              {pages.length === 0 ? (
                <tr><td colSpan={5}><div className="empty-state"><i className="bi bi-file-earmark-text" /><h4>No pages yet</h4><p>Create your first page to get started.</p></div></td></tr>
              ) : pages.map(p => (
                <tr key={p.id}>
                  <td><strong style={{ color: 'var(--text-primary)' }}>{p.title}</strong></td>
                  <td><code className="share-code-label">/page/{p.slug}</code></td>
                  <td>{p.is_published ? <span className="badge-admin badge-success">Published</span> : <span className="badge-admin badge-warning">Draft</span>}</td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{formatTime(p.updated_at)}</td>
                  <td>
                    <div className="d-flex gap-2">
                      <button className="btn btn-icon btn-admin-outline" onClick={() => editPage(p.id)} title="Edit"><i className="bi bi-pencil" /></button>
                      <button className="btn btn-icon btn-admin-outline" onClick={() => setDeleting(p)} title="Delete" style={{ color: 'var(--accent-red)' }}><i className="bi bi-trash" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <AdminModal visible={!!deleting} title="Delete Page" onClose={() => setDeleting(null)} footer={
        <><button className="btn btn-sm btn-admin-outline" onClick={() => setDeleting(null)}>Cancel</button><button className="btn btn-sm btn-admin-danger" onClick={confirmDelete}>Delete Page</button></>
      }>
        <div className="confirm-dialog">
          <i className="bi bi-exclamation-triangle-fill" />
          <h3>Delete &quot;{deleting?.title}&quot;?</h3>
          <p>This action cannot be undone.</p>
        </div>
      </AdminModal>
    </>
  );
}
