'use client';
import { useState, useEffect, useCallback } from 'react';
import { adminApi, formatTime, type ActivityItem } from './adminUtils';
import { useToast } from './AdminToast';

const LIMIT = 20;

export default function ActivitySection() {
  const { toast } = useToast();
  const [items, setItems] = useState<ActivityItem[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);

  const load = useCallback((off: number) => {
    adminApi<{ items: ActivityItem[]; total: number }>(`/activity?limit=${LIMIT}&offset=${off}`)
      .then(d => { setItems(d.items || []); setTotal(d.total || 0); setOffset(off); })
      .catch(e => toast('Failed to load activity: ' + e.message, 'error'));
  }, [toast]);

  useEffect(() => { load(0); }, [load]);

  return (
    <div className="admin-card">
      <div className="admin-card-header">
        <h3 className="admin-card-title">Activity Log</h3>
        <span className="badge-admin badge-info">{total} entries</span>
      </div>
      <div className="admin-card-body">
        {items.length === 0 ? (
          <div className="empty-state"><i className="bi bi-inbox" /><h4>No activity yet</h4></div>
        ) : (
          <ul className="activity-feed">
            {items.map((item, i) => (
              <li key={i} className="activity-item">
                <div className={`activity-dot ${(item.action || '').split('.')[0]}`} />
                <div>
                  <div className="activity-text"><strong>{item.action}</strong> — {item.details}</div>
                  <div className="activity-time">{formatTime(item.created_at)} · {item.admin_username}</div>
                </div>
              </li>
            ))}
          </ul>
        )}
        {total > LIMIT && (
          <div className="d-flex justify-between mt-3">
            <button className="btn btn-sm btn-admin-outline" disabled={offset === 0} onClick={() => load(Math.max(0, offset - LIMIT))}>
              <i className="bi bi-chevron-left" /> Previous
            </button>
            <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)', alignSelf: 'center' }}>{offset + 1}–{Math.min(offset + LIMIT, total)} of {total}</span>
            <button className="btn btn-sm btn-admin-outline" disabled={offset + LIMIT >= total} onClick={() => load(offset + LIMIT)}>
              Next <i className="bi bi-chevron-right" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
