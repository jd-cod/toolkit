'use client';

import { useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import ResultActions from './ResultActions';
import { api } from '@/lib/api';
import type { CreatedShare, ShareOptions } from '@/lib/share';

/** What the classic dashboard script exposes about the analysis it is showing. */
interface DashboardResultActions {
  readOnly: boolean;
  inputSource: string;
  logText: string;
  downloadHtml: () => void;
  downloadCsv: () => void;
}

interface DashboardRuntime {
  getResultActions?: () => DashboardResultActions | null;
  getResultActionsRevision?: () => number;
}

const ACTIONS_EVENT = 'signal:dashboard-actions';
const MOUNT_ID = 'dash-result-actions';

const dashboard = () => (window as Window & { Dashboard?: DashboardRuntime }).Dashboard;

function subscribe(onChange: () => void) {
  window.addEventListener(ACTIONS_EVENT, onChange);
  return () => window.removeEventListener(ACTIONS_EVENT, onChange);
}
const getRevision = () => dashboard()?.getResultActionsRevision?.() ?? 0;
const getServerRevision = () => 0;

const TERMINAL_INGEST_REASON =
  'Sharing is disabled for terminal-ingested logs to enforce the zero-retention policy. Use Download HTML for a self-contained offline report.';

/** Uploads the analysed log to storage, then publishes it as a share with the chosen options. */
async function createLogShare(logText: string, options: ShareOptions): Promise<CreatedShare> {
  if (!logText) throw new Error('There is no log content to share for this analysis.');

  const response = await fetch('/api/storage/upload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: logText, title: options.title }),
  });
  const upload = await response.json().catch(() => ({ error: `HTTP ${response.status}` })) as { shareCode?: string; error?: string };
  if (!response.ok || !upload.shareCode) throw new Error(`Upload failed: ${upload.error || `HTTP ${response.status}`}`);

  return api.createShare({ ...options, shareCode: upload.shareCode });
}

/**
 * Puts the shared Share / Download HTML / Download CSV bar into the Traffic
 * Analyzer dashboard. The dashboard is drawn by a classic script that replaces
 * its toolbar on every render, so this follows the dashboard's revision
 * counter and re-attaches to the current toolbar node each time.
 */
export default function NginxResultActions() {
  const revision = useSyncExternalStore(subscribe, getRevision, getServerRevision);
  if (revision === 0) return null;

  const mount = document.getElementById(MOUNT_ID);
  const actions = dashboard()?.getResultActions?.();
  if (!mount || !actions) return null;

  const { logText } = actions;
  const terminalIngest = actions.inputSource === 'terminal_ingest';

  return createPortal(
    <ResultActions
      share={actions.readOnly ? undefined : {
        heading: 'Share Analysis',
        title: 'Traffic Log Analysis',
        create: (options) => createLogShare(logText, options),
      }}
      shareDisabledReason={!actions.readOnly && terminalIngest ? TERMINAL_INGEST_REASON : undefined}
      html={{ onClick: actions.downloadHtml }}
      csv={{ onClick: actions.downloadCsv }}
    />,
    mount,
  );
}
