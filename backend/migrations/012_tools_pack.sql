-- ============================================================
-- SysAdmin Toolkit — Migration 012: tools pack (2026-11)
-- ============================================================
-- Registers the 16 tools added in the 2026-11 tools pack. See
-- docs/TOOLS_ROADMAP.md for what each one does and why it was added.
--
-- Registry rows only: none of these tools has a table of its own.
-- INSERT IGNORE so a row an admin has already edited is never overwritten.
-- sort_order continues after `password` (11) and stays unique, which the
-- homepage ordering relies on (see tests/e2e/tool-order.spec.ts).
--
-- Numbered 012 because the unmerged `security-hardening` and
-- `share-functionality` branches each already add a migration numbered 011.
-- ============================================================

USE sysadmin_toolkit;

INSERT IGNORE INTO tools (tool_key, label, description, icon, color, tags, is_enabled, sort_order) VALUES
  ('email-auth', 'SPF, DKIM & DMARC Checker', 'Check a domain''s MX, SPF, DKIM, DMARC, MTA-STS and BIMI records and get clear findings on what to fix.', 'bi-envelope-check-fill', '#0ea5e9', 'Email,SPF,DKIM,DMARC', 1, 12),
  ('blacklist', 'Blacklist (DNSBL) Check', 'Check whether an IP address or mail server is listed on common DNS blacklists.', 'bi-slash-circle-fill', '#ef4444', 'Email,Blacklist,DNSBL,Reputation', 1, 13),
  ('email-headers', 'Email Header Analyzer', 'Paste raw email headers to trace relay hops, delays and SPF, DKIM and DMARC results. 100% client-side.', 'bi-envelope-open-fill', '#8b5cf6', 'Email,Headers,Offline', 1, 14),
  ('smtp-test', 'SMTP Server Test', 'Connect to a mail server and review its banner, extensions, STARTTLS support and certificate. No message is sent.', 'bi-send-check-fill', '#14b8a6', 'Email,SMTP,STARTTLS', 1, 15),
  ('http-headers', 'HTTP Headers & Redirect Checker', 'Inspect response headers, follow the redirect chain and audit security headers for any public URL.', 'bi-arrow-left-right', '#3b82f6', 'HTTP,Redirects,Security headers', 1, 16),
  ('port-check', 'Open Port Checker', 'Test whether TCP ports on your server or public IP are reachable from the internet.', 'bi-door-open-fill', '#f97316', 'Ports,TCP,Firewall', 1, 17),
  ('cert-decoder', 'Certificate & CSR Decoder', 'Decode PEM certificates and CSRs and check that a private key matches. 100% client-side.', 'bi-file-earmark-lock-fill', '#ec4899', 'TLS,Certificates,CSR,Offline', 1, 18),
  ('sshd-audit', 'SSH Config Auditor', 'Paste an sshd_config to find risky settings and get a hardened snippet. 100% client-side.', 'bi-terminal-fill', '#22c55e', 'SSH,Hardening,Linux,Offline', 1, 19),
  ('systemd-timer', 'systemd Timer Generator', 'Convert a cron schedule to OnCalendar and generate .timer and .service unit files.', 'bi-stopwatch-fill', '#a855f7', 'systemd,Timers,Linux', 1, 20),
  ('firewall-rules', 'Firewall Rule Generator', 'Generate one rule for ufw, firewalld, nftables, iptables and Windows Firewall.', 'bi-bricks', '#f59e0b', 'Firewall,ufw,iptables,nftables', 1, 21),
  ('rsync', 'rsync Command Builder', 'Build an rsync command from options, with every flag explained.', 'bi-arrow-repeat', '#06b6d4', 'rsync,Backup,Linux', 1, 22),
  ('auth-log', 'SSH Auth Log Analyzer', 'Find brute-force sources, targeted users and successful logins in auth.log. 100% client-side.', 'bi-person-lock', '#10b981', 'SSH,Logs,Security,Offline', 1, 23),
  ('mail-log', 'Mail Log Analyzer', 'Summarize Postfix logs: delivered, deferred and bounced mail, rejects and failed logins. 100% client-side.', 'bi-mailbox', '#6366f1', 'Postfix,Logs,Email,Offline', 1, 24),
  ('windows-events', 'Windows Event ID Lookup', 'Look up common Windows Event IDs, logon types and failure codes.', 'bi-journal-text', '#0078d4', 'Windows,Event Viewer,Security', 1, 25),
  ('windows-errors', 'Windows Error Code Lookup', 'Decode Win32, HRESULT, NTSTATUS, Windows Update and stop codes.', 'bi-bug-fill', '#2563eb', 'Windows,Errors,HRESULT', 1, 26),
  ('robocopy', 'Robocopy Command Builder', 'Build a robocopy command from options, with switches and exit codes explained.', 'bi-copy', '#0891b2', 'Windows,Robocopy,Backup', 1, 27);
