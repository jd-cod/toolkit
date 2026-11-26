'use client';
import { useState, useEffect } from 'react';
import { adminApi, formatTime } from './adminUtils';
import { useToast } from './AdminToast';

interface DashboardStats {
  total_pages: number;
  total_tools: number;
  enabled_tools: number;
  total_menus: number;
  total_activities: number;
  total_shares: number;
  maintenance_mode: boolean;
  announcement_active: boolean;
}

interface ActivityItem {
  action: string;
  details: string;
  created_at: string;
  admin_username: string;
}

interface RefreshDatabaseStatus {
  name: string;
  description: string;
  edition_id: string;
  version: string;
  last_updated_at: string;
  size_bytes: number | null;
  file_mtime: string;
}

interface RefreshStatus {
  rdap: {
    bootstrap_url: string;
    refresh_interval_ms: number;
    mappings_count: number;
    last_refreshed_at: string;
    next_refresh_at: string;
  };
  geoip: {
    updater_enabled: boolean;
    refresh_interval_ms: number;
    public_dir: string;
    metadata_path: string;
    version: string;
    last_attempted_at: string;
    last_successful_update_at: string;
    last_error: string;
    editions: string[];
    databases: Record<string, RefreshDatabaseStatus>;
  };
  ip2location?: {
    enabled: boolean;
    configured: boolean;
    attribution_required: boolean;
    refresh_interval_ms: number;
    last_attempted_at: string;
    last_successful_update_at: string;
    last_error: string;
    packages: Record<string, {
      label: string;
      package_code: string;
      table: string;
      rows: number | null;
      last_table_update_at: string;
    }>;
  };
}

interface DashboardResponse {
  stats: DashboardStats;
  system_refresh: RefreshStatus;
  recent_activity: ActivityItem[];
}

export default function DashboardSection() {
  const { toast } = useToast();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [refreshStatus, setRefreshStatus] = useState<RefreshStatus | null>(null);
  const [activity, setActivity] = useState<ActivityItem[]>([]);

  useEffect(() => {
    adminApi<DashboardResponse>('/dashboard')
      .then((d) => {
        setStats(d.stats);
        setRefreshStatus(d.system_refresh);
        setActivity(d.recent_activity || []);
      })
      .catch(e => toast('Failed to load dashboard: ' + e.message, 'error'));
  }, [toast]);

  if (!stats) return <div className="skeleton" style={{ width: '100%', height: 200 }} />;

  const cards = [
    { label: 'Total Pages', value: stats.total_pages, color: 'var(--accent-cyan)', icon: 'bi-file-earmark-text-fill' },
    { label: 'Active Tools', value: `${stats.enabled_tools}/${stats.total_tools}`, color: 'var(--accent-primary)', icon: 'bi-tools' },
    { label: 'Menu Items', value: stats.total_menus, color: 'var(--accent-green)', icon: 'bi-list-ul' },
    { label: 'Activities', value: stats.total_activities, color: 'var(--accent-purple)', icon: 'bi-clock-history' },
    { label: 'Shared Links', value: stats.total_shares, color: 'var(--accent-amber)', icon: 'bi-share-fill' },
    { label: 'Maintenance', value: stats.maintenance_mode ? 'ON' : 'OFF', color: stats.maintenance_mode ? 'var(--accent-red)' : 'var(--accent-green)', icon: 'bi-exclamation-triangle-fill' },
  ];

  return (
    <>
      <div className="stats-grid">
        {cards.map((c, i) => (
          <div key={i} className="stat-card-admin">
            <div className="stat-icon-admin" style={{ color: c.color }}><i className={`bi ${c.icon}`} /></div>
            <div className="stat-value-admin" style={{ color: c.color }}>{c.value}</div>
            <div className="stat-label-admin">{c.label}</div>
          </div>
        ))}
      </div>

      {refreshStatus && (
        <div className="admin-card">
          <div className="admin-card-header">
            <h3 className="admin-card-title"><i className="bi bi-arrow-repeat" style={{ marginRight: 8, opacity: 0.6 }} />Refresh Status</h3>
          </div>
          <div className="admin-card-body">
            <div style={{ display: 'grid', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(240px,1fr))', gap: 14 }}>
                <RefreshCard
                  title="RDAP Bootstrap"
                  value={formatTime(refreshStatus.rdap.last_refreshed_at) || 'Not refreshed yet'}
                  subtitle={`Next refresh: ${formatTime(refreshStatus.rdap.next_refresh_at) || 'Pending'} · ${refreshStatus.rdap.mappings_count} TLDs`}
                />
                <RefreshCard
                  title="MaxMind Databases"
                  value={formatTime(refreshStatus.geoip.last_successful_update_at) || 'Not updated yet'}
                  subtitle={
                    refreshStatus.geoip.updater_enabled
                      ? `Daily updater active · Version ${refreshStatus.geoip.version || 'Unknown'}`
                      : 'Updater disabled: set MAXMIND_LICENSE_KEY'
                  }
                  tone={refreshStatus.geoip.updater_enabled ? 'good' : 'warn'}
                />
                {refreshStatus.ip2location?.enabled && (
                  <RefreshCard
                    title="IP2Location LITE"
                    value={formatTime(refreshStatus.ip2location.last_successful_update_at) || 'Not imported yet'}
                    subtitle={
                      refreshStatus.ip2location.configured
                        ? 'Updater active · Attribution required'
                        : 'Enabled but download token missing'
                    }
                    tone={refreshStatus.ip2location.configured ? 'good' : 'warn'}
                  />
                )}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(260px,1fr))', gap: 14 }}>
                <RefreshDetail label="RDAP Last Refresh" value={formatTime(refreshStatus.rdap.last_refreshed_at) || 'Not refreshed yet'} />
                <RefreshDetail label="RDAP Next Refresh" value={formatTime(refreshStatus.rdap.next_refresh_at) || 'Pending'} />
                <RefreshDetail label="MaxMind Last Attempt" value={formatTime(refreshStatus.geoip.last_attempted_at) || 'Never'} />
                <RefreshDetail label="MaxMind Last Success" value={formatTime(refreshStatus.geoip.last_successful_update_at) || 'Never'} />
                {refreshStatus.ip2location?.enabled && (
                  <>
                    <RefreshDetail label="IP2Location Last Attempt" value={formatTime(refreshStatus.ip2location.last_attempted_at) || 'Never'} />
                    <RefreshDetail label="IP2Location Last Success" value={formatTime(refreshStatus.ip2location.last_successful_update_at) || 'Never'} />
                  </>
                )}
              </div>

              {refreshStatus.geoip.last_error && (
                <div className="empty-state" style={{ alignItems: 'flex-start', textAlign: 'left' }}>
                  <i className="bi bi-exclamation-triangle" />
                  <h4 style={{ marginBottom: 6 }}>MaxMind updater error</h4>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.92rem' }}>{refreshStatus.geoip.last_error}</div>
                </div>
              )}

              {refreshStatus.ip2location?.enabled && refreshStatus.ip2location.last_error && (
                <div className="empty-state" style={{ alignItems: 'flex-start', textAlign: 'left' }}>
                  <i className="bi bi-exclamation-triangle" />
                  <h4 style={{ marginBottom: 6 }}>IP2Location updater error</h4>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.92rem' }}>{refreshStatus.ip2location.last_error}</div>
                </div>
              )}

              <div style={{ display: 'grid', gap: 10 }}>
                {Object.entries(refreshStatus.geoip.databases).map(([filename, db]) => (
                  <div key={filename} className="stat-card-admin" style={{ textAlign: 'left' }}>
                    <div className="stat-label-admin" style={{ marginBottom: 8 }}>{db.name}</div>
                    <div style={{ color: 'var(--text-primary)', fontWeight: 700, marginBottom: 6 }}>{filename}</div>
                    <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginBottom: 4 }}>
                      Last file update: {formatTime(db.last_updated_at || db.file_mtime) || 'Unknown'}
                    </div>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                      Version: {db.version || refreshStatus.geoip.version || 'Unknown'} · Size: {formatBytes(db.size_bytes)}
                    </div>
                  </div>
                ))}
              </div>

              {refreshStatus.ip2location?.enabled && (
                <div style={{ display: 'grid', gap: 10 }}>
                  {Object.entries(refreshStatus.ip2location.packages).map(([key, pkg]) => (
                    <div key={key} className="stat-card-admin" style={{ textAlign: 'left' }}>
                      <div className="stat-label-admin" style={{ marginBottom: 8 }}>{pkg.label}</div>
                      <div style={{ color: 'var(--text-primary)', fontWeight: 700, marginBottom: 6 }}>{pkg.package_code} · {pkg.table}</div>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginBottom: 4 }}>
                        Last table update: {formatTime(pkg.last_table_update_at) || 'Unknown'}
                      </div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                        Rows: {pkg.rows === null ? 'Unavailable' : pkg.rows.toLocaleString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="admin-card">
        <div className="admin-card-header">
          <h3 className="admin-card-title"><i className="bi bi-clock-history" style={{ marginRight: 8, opacity: 0.6 }} />Recent Activity</h3>
        </div>
        <div className="admin-card-body">
          {activity.length === 0 ? (
            <div className="empty-state"><i className="bi bi-inbox" /><h4>No activity yet</h4></div>
          ) : (
            <ul className="activity-feed">
              {activity.map((item, i: number) => (
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
        </div>
      </div>
    </>
  );
}

function RefreshCard({
  title,
  value,
  subtitle,
  tone = 'neutral',
}: {
  title: string;
  value: string;
  subtitle: string;
  tone?: 'neutral' | 'good' | 'warn';
}) {
  const color = tone === 'good' ? 'var(--accent-green)' : tone === 'warn' ? 'var(--accent-amber)' : 'var(--accent-cyan)';
  return (
    <div className="stat-card-admin" style={{ textAlign: 'left' }}>
      <div className="stat-label-admin" style={{ marginBottom: 8 }}>{title}</div>
      <div className="stat-value-admin" style={{ color, fontSize: '1.2rem', textAlign: 'left' }}>{value}</div>
      <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 6 }}>{subtitle}</div>
    </div>
  );
}

function RefreshDetail({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat-card-admin" style={{ textAlign: 'left' }}>
      <div className="stat-label-admin" style={{ marginBottom: 8 }}>{label}</div>
      <div style={{ color: 'var(--text-primary)', fontWeight: 700 }}>{value}</div>
    </div>
  );
}

function formatBytes(value: number | null) {
  if (typeof value !== 'number' || Number.isNaN(value)) return 'Unknown';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}
