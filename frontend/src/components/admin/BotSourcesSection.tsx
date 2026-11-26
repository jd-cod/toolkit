'use client';

import { useState, useEffect, useCallback } from 'react';
import { adminApi, formatTime, errorMessage } from './adminUtils';
import { useToast } from './AdminToast';
import AdminModal from './AdminModal';

interface BotSource {
  id: number;
  bot_key: string;
  display_name: string;
  group_name: string | null;
  feed_url: string;
  format: 'json_prefixes' | 'json_synctoken' | 'plain_text';
  is_enabled: number;
  last_synced_at: string | null;
  last_status: 'ok' | 'error' | 'pending';
  last_error: string | null;
  total_cidrs: number;
  created_at: string;
  updated_at: string;
}

export default function BotSourcesSection() {
  const { toast } = useToast();
  const [sources, setSources] = useState<BotSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncingAll, setSyncingAll] = useState(false);
  const [syncingId, setSyncingId] = useState<number | null>(null);

  // Modal states
  const [modalOpen, setModalOpen] = useState(false);
  const [editItem, setEditItem] = useState<BotSource | null>(null);
  const [form, setForm] = useState({
    bot_key: '',
    display_name: '',
    group_name: '',
    feed_url: '',
    format: 'json_prefixes' as 'json_prefixes' | 'json_synctoken' | 'plain_text',
    is_enabled: true,
  });
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<BotSource | null>(null);

  const loadSources = useCallback(async () => {
    try {
      const data = await adminApi<{ sources: BotSource[] }>('/bot-sources');
      setSources(data.sources || []);
    } catch (e) {
      toast('Failed to load bot sources: ' + errorMessage(e), 'error');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadSources();
  }, [loadSources]);

  const updateForm = <K extends keyof typeof form>(key: K, value: typeof form[K]) => {
    setForm(prev => ({ ...prev, [key]: value }));
  };

  function openCreate() {
    setEditItem(null);
    setForm({
      bot_key: '',
      display_name: '',
      group_name: '',
      feed_url: '',
      format: 'json_prefixes',
      is_enabled: true,
    });
    setModalOpen(true);
  }

  function openEdit(source: BotSource) {
    setEditItem(source);
    setForm({
      bot_key: source.bot_key,
      display_name: source.display_name,
      group_name: source.group_name || '',
      feed_url: source.feed_url,
      format: source.format,
      is_enabled: Boolean(source.is_enabled),
    });
    setModalOpen(true);
  }

  async function handleSave() {
    if (!form.bot_key.trim() || !form.display_name.trim() || !form.feed_url.trim()) {
      toast('Bot key, display name, and feed URL are required', 'error');
      return;
    }

    setSaving(true);
    try {
      if (editItem) {
        await adminApi(`/bot-sources/${editItem.id}`, {
          method: 'PUT',
          body: {
            bot_key: form.bot_key,
            display_name: form.display_name,
            group_name: form.group_name || null,
            feed_url: form.feed_url,
            format: form.format,
            is_enabled: form.is_enabled ? 1 : 0,
          },
        });
        toast('Bot source updated successfully!');
      } else {
        await adminApi('/bot-sources', {
          method: 'POST',
          body: {
            bot_key: form.bot_key,
            display_name: form.display_name,
            group_name: form.group_name || null,
            feed_url: form.feed_url,
            format: form.format,
            is_enabled: form.is_enabled ? 1 : 0,
          },
        });
        toast('Bot source added and synced!');
      }
      setModalOpen(false);
      await loadSources();
    } catch (e) {
      toast('Failed to save: ' + errorMessage(e), 'error');
    } finally {
      setSaving(false);
    }
  }

  async function handleToggleEnabled(source: BotSource, enabled: boolean) {
    try {
      await adminApi(`/bot-sources/${source.id}`, {
        method: 'PUT',
        body: { is_enabled: enabled ? 1 : 0 },
      });
      toast(enabled ? `Enabled ${source.display_name}` : `Disabled ${source.display_name}`);
      await loadSources();
    } catch (e) {
      toast('Failed to update: ' + errorMessage(e), 'error');
    }
  }

  async function handleSyncSingle(source: BotSource) {
    setSyncingId(source.id);
    try {
      const res = await adminApi<{ success: boolean; result: { status: string; total_cidrs?: number; error?: string } }>('/bot-sources/sync', {
        method: 'POST',
        body: { id: source.id },
      });
      if (res.result?.status === 'ok') {
        toast(`Synced ${source.display_name}: ${res.result.total_cidrs} CIDRs verified.`);
      } else {
        toast(`Sync error for ${source.display_name}: ${res.result?.error || 'Unknown error'}`, 'error');
      }
      await loadSources();
    } catch (e) {
      toast('Sync failed: ' + errorMessage(e), 'error');
    } finally {
      setSyncingId(null);
    }
  }

  async function handleSyncAll() {
    setSyncingAll(true);
    try {
      const res = await adminApi<{ success: boolean; result: { compiled?: { total_cidrs: number } } }>('/bot-sources/sync', {
        method: 'POST',
        body: { all: true },
      });
      const total = res.result?.compiled?.total_cidrs || 0;
      toast(`All bot sources synced! Total verified CIDRs: ${total}`);
      await loadSources();
    } catch (e) {
      toast('Sync all failed: ' + errorMessage(e), 'error');
    } finally {
      setSyncingAll(false);
    }
  }

  async function confirmDelete() {
    if (!deleting) return;
    try {
      await adminApi(`/bot-sources/${deleting.id}`, { method: 'DELETE' });
      toast(`Bot source "${deleting.display_name}" deleted.`);
      setDeleting(null);
      await loadSources();
    } catch (e) {
      toast('Delete failed: ' + errorMessage(e), 'error');
    }
  }

  // Summary counts
  const totalSources = sources.length;
  const enabledSources = sources.filter(s => Boolean(s.is_enabled)).length;
  const totalCidrs = sources.filter(s => Boolean(s.is_enabled)).reduce((acc, s) => acc + (s.total_cidrs || 0), 0);
  const latestSync = sources.reduce((latest, s) => {
    if (!s.last_synced_at) return latest;
    const t = new Date(s.last_synced_at).getTime();
    return t > latest ? t : latest;
  }, 0);

  return (
    <>
      {/* ─── Header Card & Metrics ─── */}
      <div className="admin-card mb-4">
        <div className="admin-card-header">
          <div>
            <h3 className="admin-card-title">
              <i className="bi bi-robot me-2 text-primary" /> Bot IP Sources & Verification Feeds
            </h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 6 }}>
              Manage official crawler IP feeds used for genuine bot verification and User-Agent spoofing detection in Nginx log analysis.
            </p>
          </div>
          <div className="d-flex align-center gap-2">
            <button
              className="btn btn-sm btn-admin-outline"
              onClick={handleSyncAll}
              disabled={syncingAll || loading}
              title="Fetch and recompile all bot IP ranges"
            >
              <i className={`bi ${syncingAll ? 'bi-arrow-repeat spin' : 'bi-arrow-clockwise'}`} />
              {syncingAll ? 'Syncing Feeds...' : 'Sync All Feeds'}
            </button>
            <button className="btn btn-sm btn-admin-primary" onClick={openCreate}>
              <i className="bi bi-plus-lg" /> Add Bot Source
            </button>
          </div>
        </div>

        <div className="admin-card-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14 }}>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px 16px', borderRadius: 10 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Configured Sources</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>{totalSources}</div>
            </div>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px 16px', borderRadius: 10 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Active Feeds</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#10b981', marginTop: 4 }}>{enabledSources}</div>
            </div>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px 16px', borderRadius: 10 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Verified CIDRs</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#6366f1', marginTop: 4 }}>{totalCidrs.toLocaleString()}</div>
            </div>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px 16px', borderRadius: 10 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Last Global Sync</div>
              <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-secondary)', marginTop: 8 }}>
                {latestSync ? formatTime(new Date(latestSync).toISOString()) : 'Never'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ─── Bot Sources Table ─── */}
      <div className="admin-card">
        <div className="admin-card-body" style={{ padding: 0 }}>
          {loading ? (
            <div className="p-4 text-center">
              <div className="skeleton mb-2" style={{ height: 36 }} />
              <div className="skeleton mb-2" style={{ height: 36 }} />
              <div className="skeleton" style={{ height: 36 }} />
            </div>
          ) : sources.length === 0 ? (
            <div className="empty-state p-4">
              <i className="bi bi-robot" />
              <h4>No bot IP sources configured</h4>
              <p>Add official bot IP feeds to enable spoof detection.</p>
              <button className="btn btn-sm btn-admin-primary mt-3" onClick={openCreate}>
                <i className="bi bi-plus-lg" /> Add Source
              </button>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Bot / Provider</th>
                    <th>Feed URL</th>
                    <th>Format</th>
                    <th style={{ textAlign: 'right' }}>Verified CIDRs</th>
                    <th>Sync Status</th>
                    <th>Last Synced</th>
                    <th style={{ textAlign: 'center' }}>Enabled</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sources.map(source => {
                    const isSyncingThis = syncingId === source.id;
                    const isError = source.last_status === 'error';
                    const isOk = source.last_status === 'ok';

                    return (
                      <tr key={source.id}>
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{source.display_name}</div>
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 2 }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                              {source.bot_key}
                            </span>
                            {source.group_name && (
                              <span style={{ fontSize: '0.7rem', padding: '1px 6px', borderRadius: 4, background: 'rgba(99, 102, 241, 0.12)', color: '#818cf8' }}>
                                {source.group_name}
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <a
                            href={source.feed_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 4,
                              maxWidth: 240,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              color: 'var(--accent-cyan)',
                              fontSize: '0.8rem',
                              fontFamily: 'var(--font-mono)',
                            }}
                            title={source.feed_url}
                          >
                            <i className="bi bi-box-arrow-up-right" style={{ fontSize: '0.7rem' }} />
                            {source.feed_url.replace(/^https?:\/\//, '')}
                          </a>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.75rem', padding: '2px 8px', borderRadius: 4, background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
                            {source.format === 'json_prefixes' ? 'JSON Prefixes' : source.format === 'json_synctoken' ? 'SyncToken' : 'Plain Text'}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: source.total_cidrs > 0 ? '#10b981' : 'var(--text-muted)' }}>
                            {source.total_cidrs.toLocaleString()}
                          </span>
                        </td>
                        <td>
                          {isOk ? (
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', color: '#10b981', fontWeight: 600 }}>
                              <i className="bi bi-check-circle-fill" /> OK
                            </span>
                          ) : isError ? (
                            <span
                              style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', color: '#ef4444', fontWeight: 600, cursor: 'help' }}
                              title={source.last_error || 'Sync failed'}
                            >
                              <i className="bi bi-exclamation-triangle-fill" /> Error
                            </span>
                          ) : (
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                              <i className="bi bi-clock-history" /> Pending
                            </span>
                          )}
                        </td>
                        <td>
                          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                            {source.last_synced_at ? formatTime(source.last_synced_at) : '—'}
                          </span>
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <label className="toggle-switch">
                            <input
                              type="checkbox"
                              checked={Boolean(source.is_enabled)}
                              onChange={e => handleToggleEnabled(source, e.target.checked)}
                            />
                            <span className="toggle-slider" />
                          </label>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', gap: 4 }}>
                            <button
                              className="btn btn-icon btn-admin-outline"
                              onClick={() => handleSyncSingle(source)}
                              disabled={isSyncingThis || syncingAll}
                              title="Sync this feed immediately"
                            >
                              <i className={`bi ${isSyncingThis ? 'bi-arrow-repeat spin' : 'bi-arrow-clockwise'}`} />
                            </button>
                            <button
                              className="btn btn-icon btn-admin-outline"
                              onClick={() => openEdit(source)}
                              title="Edit feed details"
                            >
                              <i className="bi bi-pencil" />
                            </button>
                            <button
                              className="btn btn-icon btn-admin-outline"
                              onClick={() => setDeleting(source)}
                              title="Delete source"
                              style={{ color: 'var(--accent-red)' }}
                            >
                              <i className="bi bi-trash" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* ─── Add/Edit Modal ─── */}
      <AdminModal
        visible={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editItem ? `Edit Bot Source: ${editItem.display_name}` : 'Add New Bot IP Source'}
        footer={
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button className="btn btn-sm btn-admin-outline" onClick={() => setModalOpen(false)}>
              Cancel
            </button>
            <button className="btn btn-sm btn-admin-primary" onClick={handleSave} disabled={saving}>
              <i className={`bi ${saving ? 'bi-hourglass-split' : 'bi-check-lg'}`} />
              {saving ? 'Saving...' : editItem ? 'Save Changes' : 'Add & Sync Feed'}
            </button>
          </div>
        }
      >
        <div className="form-group">
          <label className="form-label">Bot Identifier Key</label>
          <input
            className="form-input"
            value={form.bot_key}
            onChange={e => updateForm('bot_key', e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ''))}
            placeholder="e.g. googlebot, bingbot, anthropic"
            style={{ fontFamily: 'var(--font-mono)' }}
            disabled={Boolean(editItem)}
          />
          <p className="form-hint">Unique alphanumeric slug matching BotDetector bot name or category.</p>
        </div>

        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Display Name</label>
            <input
              className="form-input"
              value={form.display_name}
              onChange={e => updateForm('display_name', e.target.value)}
              placeholder="e.g. Googlebot"
            />
          </div>
          <div className="form-group">
            <label className="form-label">Group / Provider (Optional)</label>
            <input
              className="form-input"
              value={form.group_name}
              onChange={e => updateForm('group_name', e.target.value)}
              placeholder="e.g. Google, OpenAI, Microsoft"
            />
          </div>
        </div>

        <div className="form-group">
          <label className="form-label">Feed URL (JSON or Plain Text)</label>
          <input
            className="form-input"
            value={form.feed_url}
            onChange={e => updateForm('feed_url', e.target.value)}
            placeholder="https://..."
            style={{ fontFamily: 'var(--font-mono)' }}
          />
        </div>

        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Data Format</label>
            <select
              className="form-select"
              value={form.format}
              onChange={e => updateForm('format', e.target.value as BotSource['format'])}
            >
              <option value="json_prefixes">JSON with Prefixes (Google, Bing, OpenAI, Apple)</option>
              <option value="json_synctoken">JSON SyncToken (AWS, Cloudflare)</option>
              <option value="plain_text">Plain Text (CIDR list per line)</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Active State</label>
            <div style={{ paddingTop: 8 }}>
              <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.88rem' }}>
                <input
                  type="checkbox"
                  checked={form.is_enabled}
                  onChange={e => updateForm('is_enabled', e.target.checked)}
                />
                <span>Enable IP verification for this bot</span>
              </label>
            </div>
          </div>
        </div>
      </AdminModal>

      {/* ─── Delete Confirmation Modal ─── */}
      <AdminModal
        visible={Boolean(deleting)}
        onClose={() => setDeleting(null)}
        title="Confirm Deletion"
        footer={
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button className="btn btn-sm btn-admin-outline" onClick={() => setDeleting(null)}>
              Cancel
            </button>
            <button className="btn btn-sm btn-admin-danger" onClick={confirmDelete}>
              <i className="bi bi-trash" /> Delete Feed
            </button>
          </div>
        }
      >
        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
          Are you sure you want to delete bot source <strong>{deleting?.display_name}</strong> ({deleting?.bot_key})?
        </p>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
          This will remove the official IP verification ranges for this bot from the compiled database.
        </p>
      </AdminModal>
    </>
  );
}
