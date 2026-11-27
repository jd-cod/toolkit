'use client';

import './admin.css';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api';
import { ToastProvider } from '@/components/admin/AdminToast';
import DashboardSection from '@/components/admin/DashboardSection';
import SettingsSection from '@/components/admin/SettingsSection';
import PagesSection from '@/components/admin/PagesSection';
import MenusSection from '@/components/admin/MenusSection';
import ToolsSection from '@/components/admin/ToolsSection';
import FooterSection from '@/components/admin/FooterSection';
import SharesSection from '@/components/admin/SharesSection';
import AccessControlSection from '@/components/admin/AccessControlSection';
import AnnouncementSection from '@/components/admin/AnnouncementSection';
import ActivitySection from '@/components/admin/ActivitySection';
import BackupSection from '@/components/admin/BackupSection';
import ChangePasswordSection from '@/components/admin/ChangePasswordSection';
import BotSourcesSection from '@/components/admin/BotSourcesSection';
import MonitorsSection from '@/components/admin/MonitorsSection';

/* ─── Sidebar definition (matching CF admin.html structure) ─── */

const SIDEBAR_GROUPS = [
  {
    title: 'Main',
    items: [
      { key: 'dashboard', label: 'Dashboard', icon: 'bi-grid-1x2-fill' },
      { key: 'monitors', label: 'Monitors', icon: 'bi-activity' },
      { key: 'settings', label: 'Site Settings', icon: 'bi-gear-fill' },
    ],
  },
  {
    title: 'Content',
    items: [
      { key: 'pages', label: 'Pages', icon: 'bi-file-earmark-text-fill' },
      { key: 'menus', label: 'Menus', icon: 'bi-list-ul' },
      { key: 'shares', label: 'Shared Links', icon: 'bi-share-fill' },
    ],
  },
  {
    title: 'Configuration',
    items: [
      { key: 'tools', label: 'Tools', icon: 'bi-tools' },
      { key: 'bot-sources', label: 'Bot IP Sources', icon: 'bi-robot' },
      { key: 'footer', label: 'Footer', icon: 'bi-layout-text-window-reverse' },
    ],
  },
  {
    title: 'System',
    items: [
      { key: 'access-control', label: 'Access Control', icon: 'bi-shield-lock-fill' },
      { key: 'announcement', label: 'Announcement', icon: 'bi-megaphone-fill' },
      { key: 'activity', label: 'Activity Log', icon: 'bi-clock-history' },
      { key: 'backup', label: 'Backup', icon: 'bi-cloud-download-fill' },
      { key: 'password', label: 'Change Password', icon: 'bi-key-fill' },
    ],
  },
];

/* ─── Label map for the topbar ─── */
const SECTION_LABELS: Record<string, string> = {};
SIDEBAR_GROUPS.forEach(g => g.items.forEach(i => { SECTION_LABELS[i.key] = i.label; }));

/* ─── Component ─── */

export default function AdminPage() {
  const router = useRouter();
  const [user, setUser] = useState<Awaited<ReturnType<typeof api.getMe>> | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    api.getMe()
      .then(setUser)
      .catch(() => router.push('/login'))
      .finally(() => setLoading(false));
  }, [router]);

  async function handleLogout() {
    await api.logout();
    router.push('/login');
  }

  function navigate(key: string) {
    setActiveTab(key);
    setSidebarOpen(false);    // close mobile sidebar on nav
  }

  if (loading)
    return (
      <div className="admin-loading">
        <div className="skeleton" style={{ width: 200, height: 20 }} />
      </div>
    );
  if (!user) return null;

  const avatarLetter = (user.username || 'A').charAt(0).toUpperCase();

  return (
    <ToastProvider>
      <div className="admin-layout">

        {/* Mobile overlay */}
        {sidebarOpen && (
          <div className="sidebar-overlay" onClick={() => setSidebarOpen(false)} />
        )}

        {/* ─── Sidebar ─── */}
        <aside className={`admin-sidebar${sidebarOpen ? ' open' : ''}`}>
          <div className="sidebar-brand">
            <div className="sidebar-brand-icon"><i className="bi bi-shield-lock-fill" /></div>
            <div>
              <div className="sidebar-brand-text">SysAdmin Toolkit</div>
            </div>
            <span className="sidebar-brand-badge">Admin</span>
          </div>

          <nav className="sidebar-nav">
            {SIDEBAR_GROUPS.map(group => (
              <div key={group.title}>
                <div className="sidebar-section-title">{group.title}</div>
                {group.items.map(item => (
                  <button
                    key={item.key}
                    className={`sidebar-link${activeTab === item.key ? ' active' : ''}`}
                    onClick={() => navigate(item.key)}
                  >
                    <i className={`bi ${item.icon}`} aria-hidden="true" />{item.label}
                  </button>
                ))}
              </div>
            ))}
          </nav>

          <div className="sidebar-user">
            <div className="sidebar-avatar">{avatarLetter}</div>
            <div style={{ flex: 1 }}>
              <div className="sidebar-username">{user.username}</div>
              <div className="sidebar-role">Administrator</div>
            </div>
            <button
              className="btn btn-icon btn-admin-outline"
              onClick={handleLogout}
              title="Logout"
              style={{ flexShrink: 0 }}
            >
              <i className="bi bi-box-arrow-right" />
            </button>
          </div>
        </aside>

        {/* ─── Main Content ─── */}
        <main className="admin-main">
          {/* Topbar */}
          <div className="admin-topbar">
            <div className="d-flex align-center gap-2">
              <button className="mobile-menu-toggle" onClick={() => setSidebarOpen(v => !v)}>
                <i className="bi bi-list" />
              </button>
              <h1 className="topbar-title">{SECTION_LABELS[activeTab] || 'Dashboard'}</h1>
            </div>
            <div className="topbar-actions">
              <Link href="/" target="_blank" className="btn btn-sm btn-admin-outline">
                <i className="bi bi-box-arrow-up-right" /> View Site
              </Link>
            </div>
          </div>

          <div className="admin-content">
            {activeTab === 'dashboard'       && <DashboardSection />}
            {activeTab === 'monitors'        && <MonitorsSection />}
            {activeTab === 'settings'        && <SettingsSection />}
            {activeTab === 'pages'           && <PagesSection />}
            {activeTab === 'menus'           && <MenusSection />}
            {activeTab === 'shares'          && <SharesSection />}
            {activeTab === 'tools'           && <ToolsSection />}
            {activeTab === 'bot-sources'     && <BotSourcesSection />}
            {activeTab === 'footer'          && <FooterSection />}
            {activeTab === 'access-control'  && <AccessControlSection />}
            {activeTab === 'announcement'    && <AnnouncementSection />}
            {activeTab === 'activity'        && <ActivitySection />}
            {activeTab === 'backup'          && <BackupSection />}
            {activeTab === 'password'        && <ChangePasswordSection />}
          </div>
        </main>
      </div>
    </ToastProvider>
  );
}
