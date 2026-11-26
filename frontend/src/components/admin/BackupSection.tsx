'use client';
import { useState, useRef } from 'react';
import { adminApi, errorMessage } from './adminUtils';
import { useToast } from './AdminToast';

export default function BackupSection() {
  const { toast } = useToast();
  const [exporting, setExporting] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function exportBackup() {
    setExporting(true);
    try {
      const data = await adminApi('/backup');
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sysadmin-toolkit-backup-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast('Backup exported successfully!');
    } catch (e) { toast('Export failed: ' + errorMessage(e), 'error'); }
    setExporting(false);
  }

  async function restoreBackup(file: File) {
    setRestoring(true);
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      const result = await adminApi<{ operations: number }>('/backup/restore', { method: 'POST', body: data });
      toast(`Backup restored! ${result.operations} operations completed.`);
    } catch (e) { toast('Restore failed: ' + errorMessage(e), 'error'); }
    setRestoring(false);
    if (fileRef.current) fileRef.current.value = '';
  }

  return (
    <div className="admin-card">
      <div className="admin-card-header">
        <h3 className="admin-card-title">Backup & Restore</h3>
      </div>
      <div className="admin-card-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
          <div className="backup-area" onClick={exportBackup}>
            <i className="bi bi-cloud-download-fill" style={{ color: 'var(--accent-primary)' }} />
            <h4 style={{ marginBottom: 6, fontWeight: 600 }}>Export Backup</h4>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Download all settings, pages, menus, and tools as a JSON file.</p>
            <button className="btn btn-sm btn-admin-primary" style={{ marginTop: 12 }} disabled={exporting}>
              <i className={`bi ${exporting ? 'bi-hourglass-split' : 'bi-download'}`} /> {exporting ? 'Exporting...' : 'Export Now'}
            </button>
          </div>
          <div className="backup-area" onClick={() => fileRef.current?.click()}>
            <i className="bi bi-cloud-upload-fill" style={{ color: 'var(--accent-amber)' }} />
            <h4 style={{ marginBottom: 6, fontWeight: 600 }}>Restore Backup</h4>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Upload a previously exported JSON backup file to restore.</p>
            <input ref={fileRef} type="file" accept=".json" style={{ display: 'none' }} onChange={e => { if (e.target.files?.[0]) restoreBackup(e.target.files[0]); }} />
            <button className="btn btn-sm btn-admin-outline" style={{ marginTop: 12 }} disabled={restoring}>
              <i className={`bi ${restoring ? 'bi-hourglass-split' : 'bi-upload'}`} /> {restoring ? 'Restoring...' : 'Choose File'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
