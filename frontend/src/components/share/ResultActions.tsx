'use client';

import { type ButtonHTMLAttributes, type ReactNode, useState } from 'react';
import ShareDialog from './ShareDialog';
import { exportToCSV } from '@/lib/csv-utils';
import { downloadFile } from '@/lib/download';
import type { CreatedShare, ShareOptions } from '@/lib/share';

export interface ShareAction {
  /** Dialog heading, e.g. "Share DNS Snapshot". */
  heading?: string;
  /** Title pre-filled for the link. */
  title: string;
  create: (options: ShareOptions) => Promise<CreatedShare>;
  note?: ReactNode;
}

/** Either describe the file and let the bar download it, or handle the click yourself. */
export type HtmlAction = { filename: string; build: () => string } | { onClick: () => void };
export type CsvAction = { filename: string; rows: () => unknown } | { onClick: () => void };

export interface ResultActionsProps {
  /** Omit on read-only views (a shared link) and for tools whose results must not leave the browser. */
  share?: ShareAction;
  /** Sharing is not possible here: the Share button stays visible and, when clicked, shows this explanation instead of the dialog. */
  shareDisabledReason?: string;
  html?: HtmlAction;
  csv?: CsvAction;
  /** Extra tool-specific actions, shown after the standard three. Use ResultActionButton. */
  children?: ReactNode;
  className?: string;
}

/**
 * The action bar every tool shows above its results: Share, Download HTML and
 * Download CSV, always in that order and with those labels.
 */
export default function ResultActions({ share, shareDisabledReason, html, csv, children, className }: ResultActionsProps) {
  const [shareOpen, setShareOpen] = useState(false);
  const [reasonShown, setReasonShown] = useState(false);

  function downloadHtml() {
    if (!html) return;
    if ('onClick' in html) html.onClick();
    else downloadFile(html.build(), `${html.filename}.html`, 'text/html;charset=utf-8');
  }

  function downloadCsv() {
    if (!csv) return;
    if ('onClick' in csv) csv.onClick();
    else exportToCSV(csv.rows(), csv.filename);
  }

  return (
    <div className={`signal-actions${className ? ` ${className}` : ''}`} role="group" aria-label="Result actions">
      {share && !shareDisabledReason && (
        <ResultActionButton icon="share-fill" primary data-action="share" onClick={() => setShareOpen(true)}>
          Share
        </ResultActionButton>
      )}
      {shareDisabledReason && (
        <ResultActionButton
          icon="shield-lock"
          className="signal-action-unavailable"
          data-action="share"
          aria-expanded={reasonShown}
          title={shareDisabledReason}
          onClick={() => setReasonShown((shown) => !shown)}
        >
          Share
        </ResultActionButton>
      )}
      {html && (
        <ResultActionButton icon="filetype-html" data-action="download-html" onClick={downloadHtml}>
          Download HTML
        </ResultActionButton>
      )}
      {csv && (
        <ResultActionButton icon="filetype-csv" data-action="download-csv" onClick={downloadCsv}>
          Download CSV
        </ResultActionButton>
      )}
      {children}
      {shareDisabledReason && reasonShown && (
        <p className="signal-actions-note" role="status">{shareDisabledReason}</p>
      )}
      {share && !shareDisabledReason && (
        <ShareDialog
          open={shareOpen}
          onClose={() => setShareOpen(false)}
          heading={share.heading}
          defaultTitle={share.title}
          create={share.create}
          note={share.note}
        />
      )}
    </div>
  );
}

interface ResultActionButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Bootstrap icon name without the `bi-` prefix. */
  icon?: string;
  primary?: boolean;
}

/** A button styled to sit in the action bar; use it for tool-specific extras. */
export function ResultActionButton({ icon, primary, className, children, ...rest }: ResultActionButtonProps) {
  return (
    <button
      type="button"
      className={`signal-action${primary ? ' signal-action-primary' : ''}${className ? ` ${className}` : ''}`}
      {...rest}
    >
      {icon && <i className={`bi bi-${icon}`} aria-hidden="true" />}
      {children}
    </button>
  );
}
