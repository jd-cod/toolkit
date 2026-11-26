'use client';
import { useState, useEffect, useCallback } from 'react';
import { adminApi, errorMessage } from './adminUtils';
import type { MenuItem } from '@/lib/api';
import { useToast } from './AdminToast';
import AdminModal from './AdminModal';

export default function MenusSection() {
  const { toast } = useToast();
  const [menus, setMenus] = useState<MenuItem[]>([]);
  const [tab, setTab] = useState<'header' | 'footer'>('header');
  const [modalOpen, setModalOpen] = useState(false);
  const [editItem, setEditItem] = useState<MenuItem | null>(null);
  const [form, setForm] = useState({ label: '', url: '', icon: '', sort_order: 0, location: 'header', open_in_new_tab: false });
  const [deleting, setDeleting] = useState<MenuItem | null>(null);

  const load = useCallback(() => adminApi<MenuItem[]>('/menus').then(setMenus).catch(e => toast('Failed to load menus: ' + errorMessage(e), 'error')), [toast]);
  useEffect(() => { void load(); }, [load]);

  const filtered = menus.filter(m => m.location === tab).sort((a, b) => a.sort_order - b.sort_order);
  const updateForm = <K extends keyof typeof form>(k: K, v: typeof form[K]) => setForm(p => ({ ...p, [k]: v }));

  function openModal(menu?: MenuItem) {
    if (menu) {
      setEditItem(menu);
      setForm({ label: menu.label, url: menu.url, icon: menu.icon || '', sort_order: menu.sort_order, location: menu.location, open_in_new_tab: !!menu.open_in_new_tab });
    } else {
      setEditItem(null);
      setForm({ label: '', url: '', icon: '', sort_order: 0, location: tab, open_in_new_tab: false });
    }
    setModalOpen(true);
  }

  async function saveMenu() {
    if (!form.label || !form.url) { toast('Label and URL are required', 'error'); return; }
    try {
      const body = { ...form, is_visible: true };
      if (editItem) {
        await adminApi(`/menus/${editItem.id}`, { method: 'PUT', body });
        toast('Menu item updated!');
      } else {
        await adminApi('/menus', { method: 'POST', body });
        toast('Menu item added!');
      }
      setModalOpen(false);
      load();
    } catch (e) { toast('Failed to save: ' + errorMessage(e), 'error'); }
  }

  async function toggleVisibility(id: number, visible: boolean) {
    try {
      await adminApi(`/menus/${id}`, { method: 'PUT', body: { is_visible: visible } });
      toast(visible ? 'Menu item visible' : 'Menu item hidden');
      load();
    } catch (e) { toast('Failed to update: ' + errorMessage(e), 'error'); }
  }

  async function confirmDelete() {
    if (!deleting) return;
    try {
      await adminApi(`/menus/${deleting.id}`, { method: 'DELETE' });
      toast('Menu item deleted!');
      setDeleting(null);
      load();
    } catch (e) { toast('Failed to delete: ' + errorMessage(e), 'error'); }
  }

  return (
    <>
      <div className="d-flex align-center justify-between mb-4">
        <div className="d-flex gap-2">
          <button className={`menu-tab-btn ${tab === 'header' ? 'active' : ''}`} onClick={() => setTab('header')}>Header Menus</button>
          <button className={`menu-tab-btn ${tab === 'footer' ? 'active' : ''}`} onClick={() => setTab('footer')}>Footer Menus</button>
        </div>
        <button className="btn btn-sm btn-admin-primary" onClick={() => openModal()}><i className="bi bi-plus-lg" /> Add Menu Item</button>
      </div>
      <div className="admin-card">
        <div className="admin-card-body" style={{ padding: 0 }}>
          <table className="admin-table">
            <thead><tr><th>Order</th><th>Label</th><th>URL</th><th>Icon</th><th>Visible</th><th style={{ width: 120 }}>Actions</th></tr></thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={6}><div className="empty-state"><i className="bi bi-list-ul" /><h4>No {tab} menus</h4><p>Add your first menu item.</p></div></td></tr>
              ) : filtered.map(m => (
                <tr key={m.id}>
                  <td><span className="badge-admin badge-info">{m.sort_order}</span></td>
                  <td><strong style={{ color: 'var(--text-primary)' }}>{m.label}</strong></td>
                  <td><code className="share-code-label">{m.url}</code></td>
                  <td>{m.icon ? <><i className={`bi ${m.icon}`} /> {m.icon}</> : <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                  <td>
                    <label className="toggle-switch">
                      <input type="checkbox" checked={!!m.is_visible} onChange={e => toggleVisibility(m.id, e.target.checked)} />
                      <span className="toggle-slider" />
                    </label>
                  </td>
                  <td>
                    <div className="d-flex gap-2">
                      <button className="btn btn-icon btn-admin-outline" onClick={() => openModal(m)} title="Edit"><i className="bi bi-pencil" /></button>
                      <button className="btn btn-icon btn-admin-outline" onClick={() => setDeleting(m)} title="Delete" style={{ color: 'var(--accent-red)' }}><i className="bi bi-trash" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <AdminModal visible={modalOpen} title={editItem ? 'Edit Menu Item' : 'Add Menu Item'} onClose={() => setModalOpen(false)} footer={
        <><button className="btn btn-sm btn-admin-outline" onClick={() => setModalOpen(false)}>Cancel</button><button className="btn btn-sm btn-admin-primary" onClick={saveMenu}>{editItem ? 'Update' : 'Add'} Menu Item</button></>
      }>
        <div className="form-group"><label className="form-label">Label</label><input className="form-input" value={form.label} onChange={e => updateForm('label', e.target.value)} placeholder="e.g. About Us" /></div>
        <div className="form-group"><label className="form-label">URL</label><input className="form-input" value={form.url} onChange={e => updateForm('url', e.target.value)} placeholder="e.g. /page/about-us or https://..." /></div>
        <div className="form-row">
          <div className="form-group"><label className="form-label">Icon</label><input className="form-input" value={form.icon} onChange={e => updateForm('icon', e.target.value)} placeholder="e.g. bi-info-circle" /></div>
          <div className="form-group"><label className="form-label">Sort Order</label><input className="form-input" type="number" value={form.sort_order} onChange={e => updateForm('sort_order', parseInt(e.target.value) || 0)} min={0} /></div>
        </div>
        <div className="form-row">
          <div className="form-group"><label className="form-label">Location</label>
            <select className="form-select" value={form.location} onChange={e => updateForm('location', e.target.value)}><option value="header">Header</option><option value="footer">Footer</option></select>
          </div>
          <div className="form-group"><label className="form-label">Open in New Tab</label>
            <select className="form-select" value={form.open_in_new_tab ? '1' : '0'} onChange={e => updateForm('open_in_new_tab', e.target.value === '1')}><option value="0">No</option><option value="1">Yes</option></select>
          </div>
        </div>
      </AdminModal>

      <AdminModal visible={!!deleting} title="Delete Menu Item" onClose={() => setDeleting(null)} footer={
        <><button className="btn btn-sm btn-admin-outline" onClick={() => setDeleting(null)}>Cancel</button><button className="btn btn-sm btn-admin-danger" onClick={confirmDelete}>Delete</button></>
      }>
        <div className="confirm-dialog"><i className="bi bi-exclamation-triangle-fill" /><h3>Delete &quot;{deleting?.label}&quot;?</h3><p>This menu item will be permanently removed.</p></div>
      </AdminModal>
    </>
  );
}
