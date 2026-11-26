'use client';
import { useState, useEffect, useCallback } from 'react';
import { adminApi, formatTime, formatDateInputValue, errorMessage, type AdminShare, type ShareList } from './adminUtils';
import { useToast } from './AdminToast';
import AdminModal from './AdminModal';
import { SHARE_TYPE_LABELS } from '@/lib/share';

const SHARE_TYPES = Object.entries(SHARE_TYPE_LABELS);
const shareTypeLabel = (type: string) => (SHARE_TYPE_LABELS as Record<string, string>)[type] || type;

export default function SharesSection() {
  const { toast } = useToast();
  const [shares, setShares] = useState<ShareList>({ items: [], total: 0, counts: {} });
  const [filter, setFilter] = useState('all');
  const [modalOpen, setModalOpen] = useState(false);
  const [editItem, setEditItem] = useState<AdminShare | null>(null);
  const [form, setForm] = useState({ title: '', r2_key: '', source_url: '', password: '', expires_at: '' });
  const [deleting, setDeleting] = useState<AdminShare | null>(null);

  const load = useCallback(() => adminApi<ShareList>(`/shares?limit=50&offset=0&type=${filter}`).then(setShares).catch(e => toast('Failed to load shares: ' + errorMessage(e), 'error')), [filter, toast]);
  useEffect(() => { void load(); }, [load]);

  const updateForm = (k: keyof typeof form, v: string) => setForm(p => ({ ...p, [k]: v }));

  function openCreate() {
    setEditItem(null);
    setForm({ title: '', r2_key: '', source_url: '', password: '', expires_at: '' });
    setModalOpen(true);
  }

  async function editShare(code: string) {
    try {
      const s = await adminApi<AdminShare>(`/shares/${code}`);
      setEditItem(s);
      setForm({ title: s.title, r2_key: s.r2_key || '', source_url: s.source_url || '', password: '', expires_at: formatDateInputValue(s.expires_at) });
      setModalOpen(true);
    } catch (e) { toast('Failed to load share: ' + errorMessage(e), 'error'); }
  }

  async function saveShare() {
    if (!form.title || (!editItem && !form.r2_key)) { toast('Title and R2 Key are required', 'error'); return; }
    try {
      if (editItem) {
        await adminApi(`/shares/${editItem.code}`, { method: 'PUT', body: { title: form.title, r2_key: form.r2_key, source_url: form.source_url, expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null } });
        toast('Share updated!');
      } else {
        await adminApi('/shares', { method: 'POST', body: { title: form.title, r2_key: form.r2_key, source_url: form.source_url, password: form.password || undefined, expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null } });
        toast('Share created!');
      }
      setModalOpen(false);
      load();
    } catch (e) { toast('Failed to save: ' + errorMessage(e), 'error'); }
  }

  async function confirmDelete() {
    if (!deleting) return;
    try {
      await adminApi(`/shares/${deleting.code}`, { method: 'DELETE' });
      toast('Share deleted!');
      setDeleting(null);
      load();
    } catch (e) { toast('Failed to delete: ' + errorMessage(e), 'error'); }
  }

  function copyText(text: string, msg: string) {
    navigator.clipboard.writeText(text).then(() => toast(msg, 'info')).catch(() => toast('Copy failed', 'error'));
  }

  const items = shares.items || [];

  return (
    <>
      <div className="admin-card">
        <div className="admin-card-header">
          <div>
            <h3 className="admin-card-title">Shared Links</h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 6 }}>Manage shared analysis links, R2 storage, expiry rules, and access protection.</p>
          </div>
          <div className="d-flex align-center gap-2">
            <select className="form-select" style={{ minWidth: 140 }} value={filter} onChange={e => setFilter(e.target.value)}>
              <option value="all">All Shares</option>
              {SHARE_TYPES.map(([type, label]) => <option key={type} value={type}>{label} Shares</option>)}
            </select>
            <span className="badge-admin badge-info">{shares.total} links</span>
            <button className="btn btn-sm btn-admin-primary" onClick={openCreate}><i className="bi bi-plus-lg" /> Create Share</button>
          </div>
        </div>
        <div className="admin-card-body" style={{ padding: 0 }}>
          <table className="admin-table">
            <thead><tr><th>Share</th><th>Source</th><th>Expiry</th><th>Created</th><th>Status</th><th style={{ width: 120 }}>Actions</th></tr></thead>
            <tbody>
              {items.length === 0 ? (
                <tr><td colSpan={6}><div className="empty-state"><i className="bi bi-share" /><h4>No shared links yet</h4></div></td></tr>
              ) : items.map(s => (
                <tr key={s.code}>
                  <td>
                    <strong style={{ color: 'var(--text-primary)' }}>{s.title}</strong>
                    <div className="d-flex align-center gap-1" style={{ marginTop: 4 }}>
                      <span className={`badge-admin ${s.share_type === 'nginx' ? 'badge-info' : 'badge-warning'}`}>{shareTypeLabel(s.share_type)}</span>
                      <code className="share-code-label">{s.code}</code>
                      <button className="btn btn-icon btn-admin-outline" style={{ width: 24, height: 24, fontSize: '0.7rem' }} onClick={() => copyText(s.code, 'Code copied')} title="Copy code"><i className="bi bi-clipboard" /></button>
                      <button className="btn btn-icon btn-admin-outline" style={{ width: 24, height: 24, fontSize: '0.7rem' }} onClick={() => copyText(`${window.location.origin}/s/${s.code}`, 'Link copied')} title="Copy link"><i className="bi bi-link-45deg" /></button>
                    </div>
                  </td>
                  <td>{s.share_type !== 'nginx' ? <span>{s.subject}</span> : <div style={{ fontSize: '0.78rem' }}>
                    {s.r2_key && <div><span className="share-meta-text">R2 Key: </span><code>{s.r2_key}</code></div>}
                    {s.source_url && <div><span className="share-meta-text">Source: </span><a href={s.source_url} target="_blank" rel="noopener">{s.source_url.substring(0, 36)}...</a></div>}
                  </div>}</td>
                  <td>{s.expires_at ? <><div style={{ fontSize: '0.82rem' }}>{formatTime(s.expires_at)}</div><div className="share-meta-text">{s.is_expired ? 'Expired' : 'Scheduled'}</div></> : <span className="share-meta-text">Never</span>}</td>
                  <td><span className="share-meta-text">{formatTime(s.created_at)}</span></td>
                  <td>
                    <div className="share-badge-stack">
                      <span className={`badge-admin ${s.is_expired ? 'badge-danger' : 'badge-success'}`}>{s.is_expired ? 'Expired' : 'Active'}</span>
                      {s.has_password && <span className="badge-admin badge-warning">Password</span>}
                    </div>
                  </td>
                  <td>
                    <div className="d-flex gap-2">
                      {s.share_type === 'nginx' && <button className="btn btn-icon btn-admin-outline" onClick={() => editShare(s.code)} title="Edit"><i className="bi bi-pencil" /></button>}
                      <button className="btn btn-icon btn-admin-outline" onClick={() => setDeleting(s)} title="Delete" style={{ color: 'var(--accent-red)' }}><i className="bi bi-trash" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <AdminModal visible={modalOpen} title={editItem ? 'Edit Shared Link' : 'Create Shared Link'} onClose={() => setModalOpen(false)} footer={
        <><button className="btn btn-sm btn-admin-outline" onClick={() => setModalOpen(false)}>Cancel</button><button className="btn btn-sm btn-admin-primary" onClick={saveShare}>{editItem ? 'Update' : 'Create'} Share</button></>
      }>
        <div className="form-group"><label className="form-label">Title</label><input className="form-input" value={form.title} onChange={e => updateForm('title', e.target.value)} placeholder="e.g. Production Nginx Analysis" /></div>
        <div className="form-group"><label className="form-label">R2 Key / Storage Path</label><input className="form-input" value={form.r2_key} onChange={e => updateForm('r2_key', e.target.value)} placeholder="shares/abc12345.log.gz" /><p className="form-hint">Cloudflare R2 object key.</p></div>
        <div className="form-group"><label className="form-label">Source URL (optional)</label><input className="form-input" value={form.source_url} onChange={e => updateForm('source_url', e.target.value)} placeholder="https://example.com/log.txt" /><p className="form-hint">Original remote URL if uploaded from external source.</p></div>
        <div className="form-row">
          <div className="form-group"><label className="form-label">Expiry</label><input className="form-input" type="datetime-local" value={form.expires_at} onChange={e => updateForm('expires_at', e.target.value)} /><p className="form-hint">Leave empty for indefinite.</p></div>
        </div>
        {!editItem && <div className="form-group"><label className="form-label">Password (optional)</label><input className="form-input" type="password" value={form.password} onChange={e => updateForm('password', e.target.value)} placeholder="Leave empty for no password" /></div>}
        {editItem && <div className="form-group"><label className="form-label">Share Code</label><div className="d-flex align-center gap-2"><code className="share-code-label">{editItem.code}</code><button className="btn btn-sm btn-admin-outline" onClick={() => copyText(`${window.location.origin}/s/${editItem.code}`, 'Link copied')}><i className="bi bi-link-45deg" /> Copy Link</button></div></div>}
      </AdminModal>

      <AdminModal visible={!!deleting} title="Delete Share" onClose={() => setDeleting(null)} footer={
        <><button className="btn btn-sm btn-admin-outline" onClick={() => setDeleting(null)}>Cancel</button><button className="btn btn-sm btn-admin-danger" onClick={confirmDelete}>Delete</button></>
      }>
        <div className="confirm-dialog"><i className="bi bi-exclamation-triangle-fill" /><h3>Delete &quot;{deleting?.title}&quot;?</h3><p>This shared link will be permanently removed.</p></div>
      </AdminModal>
    </>
  );
}
