'use client';

import { type FormEvent, type ReactNode, useEffect, useId, useRef, useState } from 'react';
import { useClipboard } from '@/hooks/useClipboard';
import {
  DEFAULT_SHARE_EXPIRY,
  SHARE_EXPIRY_OPTIONS,
  describeShare,
  shareLink,
  sharePasswordError,
  type CreatedShare,
  type ShareExpiry,
  type ShareOptions,
} from '@/lib/share';

export interface ShareDialogProps {
  open: boolean;
  onClose: () => void;
  /** Dialog heading, e.g. "Share DNS Snapshot". */
  heading?: string;
  /** Title pre-filled for the link. */
  defaultTitle: string;
  /** Creates the share and resolves with its code. Rejects with an Error to show a message. */
  create: (options: ShareOptions) => Promise<CreatedShare>;
  /** Optional extra line shown under the form fields. */
  note?: ReactNode;
}

/**
 * The one share dialog used by every tool: title, expiry and optional
 * password, then the created link with a copy button.
 */
export default function ShareDialog({ open, onClose, heading = 'Share Results', defaultTitle, create, note }: ShareDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const headingId = useId();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      dialog.showModal();
      // showModal focuses the first control, the close button; start in the form instead.
      dialog.querySelector<HTMLElement>('[data-initial-focus]')?.focus();
    }
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={dialogRef}
      className="signal-share-dialog"
      aria-labelledby={headingId}
      onClose={onClose}
      onClick={(event) => { if (event.target === event.currentTarget) onClose(); }}
    >
      {open && (
        <div className="signal-share-dialog-panel">
          <header className="signal-share-dialog-header">
            <h2 id={headingId}><i className="bi bi-share-fill" aria-hidden="true" />{heading}</h2>
            <button type="button" className="signal-share-dialog-close" onClick={onClose} aria-label="Close">
              <i className="bi bi-x-lg" aria-hidden="true" />
            </button>
          </header>
          <ShareForm defaultTitle={defaultTitle} create={create} note={note} onClose={onClose} />
        </div>
      )}
    </dialog>
  );
}

interface CreatedLink {
  url: string;
  summary: string;
}

function ShareForm({ defaultTitle, create, note, onClose }: Pick<ShareDialogProps, 'defaultTitle' | 'create' | 'note' | 'onClose'>) {
  const { copy, isCopied } = useClipboard();
  const fieldId = useId();
  const [title, setTitle] = useState(defaultTitle);
  const [expiry, setExpiry] = useState<ShareExpiry>(DEFAULT_SHARE_EXPIRY);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [link, setLink] = useState<CreatedLink | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;

    const passwordProblem = sharePasswordError(password);
    if (passwordProblem) {
      setError(passwordProblem);
      return;
    }

    setBusy(true);
    setError('');
    try {
      const trimmedPassword = password.trim();
      const created = await create({ title: title.trim() || defaultTitle, expiry, password: trimmedPassword });
      setLink({ url: shareLink(window.location.origin, created.code), summary: describeShare(expiry, Boolean(trimmedPassword)) });
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : 'Failed to create share link.');
    } finally {
      setBusy(false);
    }
  }

  if (link) {
    return (
      <div className="signal-share-dialog-body" data-share-state="created">
        <p className="signal-share-success" role="status">
          <i className="bi bi-check-circle-fill" aria-hidden="true" />Share link created
        </p>
        <div className="signal-share-link">
          <input
            readOnly
            value={link.url}
            aria-label="Share link"
            data-share-url
            onFocus={(event) => event.currentTarget.select()}
          />
          <button type="button" className="signal-action signal-action-primary" onClick={() => void copy(link.url, 'share')}>
            <i className={isCopied('share') ? 'bi bi-check-lg' : 'bi bi-clipboard'} aria-hidden="true" />
            {isCopied('share') ? 'Copied' : 'Copy link'}
          </button>
        </div>
        <p className="signal-share-summary">{link.summary}</p>
        <div className="signal-share-dialog-footer">
          <button type="button" className="signal-action" onClick={() => { setLink(null); setError(''); }}>Create another link</button>
          <button type="button" className="signal-action" onClick={onClose}>Done</button>
        </div>
      </div>
    );
  }

  return (
    <form className="signal-share-dialog-body" onSubmit={(event) => void submit(event)} data-share-state="form">
      <div className="signal-share-field">
        <label htmlFor={`${fieldId}-title`}>Title</label>
        <input id={`${fieldId}-title`} value={title} maxLength={200} onChange={(event) => setTitle(event.target.value)} data-initial-focus />
      </div>
      <div className="signal-share-field-row">
        <div className="signal-share-field">
          <label htmlFor={`${fieldId}-expiry`}>Link expiry</label>
          <select id={`${fieldId}-expiry`} value={expiry} onChange={(event) => setExpiry(event.target.value as ShareExpiry)}>
            {SHARE_EXPIRY_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </div>
        <div className="signal-share-field">
          <label htmlFor={`${fieldId}-password`}>Password <span>(optional)</span></label>
          <div className="signal-share-password">
            <input
              id={`${fieldId}-password`}
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Leave blank for a public link"
              autoComplete="new-password"
            />
            <button
              type="button"
              onClick={() => setShowPassword((shown) => !shown)}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              aria-pressed={showPassword}
            >
              <i className={showPassword ? 'bi bi-eye-slash' : 'bi bi-eye'} aria-hidden="true" />
            </button>
          </div>
        </div>
      </div>
      {note && <div className="signal-share-note">{note}</div>}
      {error && <p className="signal-share-error" role="alert">{error}</p>}
      <div className="signal-share-dialog-footer">
        <button type="button" className="signal-action" onClick={onClose}>Cancel</button>
        <button type="submit" className="signal-action signal-action-primary" disabled={busy}>
          <i className={busy ? 'bi bi-hourglass-split' : 'bi bi-link-45deg'} aria-hidden="true" />
          {busy ? 'Creating link…' : 'Create share link'}
        </button>
      </div>
    </form>
  );
}
