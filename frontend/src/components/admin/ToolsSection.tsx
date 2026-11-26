'use client';
import { useState, useEffect, useCallback } from 'react';
import { DragDropContext, Droppable, Draggable, DropResult } from '@hello-pangea/dnd';
import { adminApi, errorMessage } from './adminUtils';
import type { Tool } from '@/lib/api';
import { useToast } from './AdminToast';
import AdminModal from './AdminModal';

export default function ToolsSection() {
  const { toast } = useToast();
  const [tools, setTools] = useState<Tool[]>([]);
  const [saving, setSaving] = useState(false);
  const [editingTool, setEditingTool] = useState<Tool | null>(null);
  const [seoForm, setSeoForm] = useState({ meta_title: '', meta_description: '', seo_noindex: false });
  const [savingSeo, setSavingSeo] = useState(false);

  const load = useCallback(() =>
    adminApi<Tool[]>('/tools')
      // `id` breaks ties: sort_order is not unique (007_password_generator_tool.sql
      // documents a past collision) and MySQL gives no ordering guarantee for peers,
      // so without it the admin list itself would reshuffle on every reload.
      .then(rows => setTools([...rows].sort((a, b) => a.sort_order - b.sort_order || a.id - b.id)))
      .catch(e => toast('Failed to load tools: ' + errorMessage(e), 'error')), [toast]);

  useEffect(() => { void load(); }, [load]);

  async function toggleEnabled(id: number, enabled: boolean) {
    try {
      await adminApi(`/tools/${id}`, { method: 'PUT', body: { is_enabled: enabled } });
      toast(enabled ? 'Tool enabled' : 'Tool disabled');
      load();
    } catch (e) { toast('Failed: ' + errorMessage(e), 'error'); }
  }

  function openSeoModal(tool: Tool) {
    setEditingTool(tool);
    setSeoForm({
      meta_title: tool.meta_title || '',
      meta_description: tool.meta_description || '',
      seo_noindex: Boolean(tool.seo_noindex),
    });
  }

  async function saveToolSeo() {
    if (!editingTool) return;
    setSavingSeo(true);
    try {
      await adminApi(`/tools/${editingTool.id}`, {
        method: 'PUT',
        body: {
          meta_title: seoForm.meta_title,
          meta_description: seoForm.meta_description,
          seo_noindex: seoForm.seo_noindex ? 1 : 0,
        },
      });
      toast(`SEO settings updated for ${editingTool.label}`);
      setEditingTool(null);
      load();
    } catch (e) {
      toast('Failed to save tool SEO: ' + errorMessage(e), 'error');
    } finally {
      setSavingSeo(false);
    }
  }

  async function onDragEnd(result: DropResult) {
    const { source, destination } = result;
    if (!destination) return;
    if (source.index === destination.index) return;

    const reordered = [...tools];
    const [moved] = reordered.splice(source.index, 1);
    reordered.splice(destination.index, 0, moved);
    setTools(reordered);   // optimistic: the list must not snap back mid-animation

    setSaving(true);
    try {
      await adminApi('/tools/reorder', {
        method: 'PUT',
        body: { items: reordered.map((t, index) => ({ id: t.id, sort_order: index + 1 })) },
      });
      toast('Tool order saved');
    } catch (e) {
      toast('Failed to save order: ' + errorMessage(e), 'error');
      load();             // re-fetch so the UI matches the database again
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <DragDropContext onDragEnd={onDragEnd}>
        <div id="tools-list">
        <Droppable droppableId="tools">
          {provided => (
            <div ref={provided.innerRef} {...provided.droppableProps}>
              {tools.length === 0 ? (
                <div className="admin-card"><div className="admin-card-body"><div className="empty-state"><i className="bi bi-tools" /><h4>No tools found</h4></div></div></div>
              ) : tools.map((t, index) => (
                <Draggable key={t.id} draggableId={String(t.id)} index={index}>
                  {(dragProvided, dragSnapshot) => (
                    // The gap lives on this wrapper, not the card: rbd measures the
                    // dragged element's box, and a card-level margin would make the
                    // drop indicator sit one gap off from where the card lands.
                    <div
                      ref={dragProvided.innerRef}
                      {...dragProvided.draggableProps}
                      className="admin-tool-row"
                      style={dragProvided.draggableProps.style}
                    >
                      <div
                        {...dragProvided.dragHandleProps}
                        className={`admin-tool-card${dragSnapshot.isDragging ? ' dragging' : ''}`}
                      >
                        <div className="admin-tool-grip" title="Drag to reorder">
                          <i className="bi bi-grip-vertical" />
                        </div>
                        <div className="admin-tool-icon" style={{ background: t.color || 'var(--accent-primary)' }}>
                          <i className={`bi ${t.icon || 'bi-wrench'}`} />
                        </div>
                        <div className="admin-tool-info">
                          <div className="d-flex align-center">
                            <span className="admin-tool-order">{index + 1}</span>
                            <span className="admin-tool-title">{t.label}</span>
                            <span className="admin-tool-key">{t.tool_key}</span>
                          </div>
                          <div className="admin-tool-desc">{t.description}</div>
                          <div className="admin-tool-tags">
                            {(t.tags || '').split(',').filter(Boolean).map((tag: string, i: number) => (
                              <span key={i} className="tool-tag">{tag.trim()}</span>
                            ))}
                          </div>
                        </div>
                        <div className="admin-tool-actions d-flex align-center gap-2">
                          <button
                            type="button"
                            className="btn btn-sm btn-admin-outline"
                            onClick={() => openSeoModal(t)}
                            title="Edit SEO settings"
                          >
                            <i className="bi bi-search" /> SEO
                          </button>
                          <label className="toggle-switch">
                            <input type="checkbox" checked={!!t.is_enabled} onChange={e => toggleEnabled(t.id, e.target.checked)} />
                            <span className="toggle-slider" />
                          </label>
                        </div>
                      </div>
                    </div>
                  )}
                </Draggable>
              ))}
              {provided.placeholder}
            </div>
          )}
        </Droppable>
      </div>
      {saving && <div className="admin-tool-saving"><i className="bi bi-arrow-repeat" /> Saving order…</div>}
    </DragDropContext>

    <AdminModal
      visible={!!editingTool}
      title={`SEO Settings — ${editingTool?.label || 'Tool'}`}
      onClose={() => setEditingTool(null)}
      footer={
        <>
          <button className="btn btn-sm btn-admin-outline" onClick={() => setEditingTool(null)} disabled={savingSeo}>
            Cancel
          </button>
          <button className="btn btn-sm btn-admin-primary" onClick={saveToolSeo} disabled={savingSeo}>
            {savingSeo ? 'Saving...' : 'Save SEO'}
          </button>
        </>
      }
    >
      <div>
        <div className="form-group mb-3">
          <label className="form-label">Custom Meta Title</label>
          <input
            className="form-input"
            value={seoForm.meta_title}
            onChange={e => setSeoForm(f => ({ ...f, meta_title: e.target.value }))}
            placeholder="Custom title tag for this tool (optional, overrides default)"
          />
          <p className="form-hint">Leave blank to use the reviewed default title for this tool.</p>
        </div>
        <div className="form-group mb-3">
          <label className="form-label">Custom Meta Description</label>
          <textarea
            className="form-textarea"
            value={seoForm.meta_description}
            onChange={e => setSeoForm(f => ({ ...f, meta_description: e.target.value }))}
            rows={3}
            placeholder="Custom meta description for this tool (optional, overrides default)"
          />
          <p className="form-hint">Leave blank to use the reviewed default description for this tool.</p>
        </div>
        <div className="form-group">
          <label className="toggle-switch-label d-flex align-center gap-2" style={{ cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={seoForm.seo_noindex}
              onChange={e => setSeoForm(f => ({ ...f, seo_noindex: e.target.checked }))}
            />
            <span style={{ fontSize: '0.85rem' }}>Exclude this tool from search engines (<code style={{ fontSize: '0.8rem' }}>noindex</code>)</span>
          </label>
          <p className="form-hint">When excluded, the tool page outputs a noindex tag and is omitted from the sitemap.</p>
        </div>
      </div>
    </AdminModal>
    </>
  );
}
