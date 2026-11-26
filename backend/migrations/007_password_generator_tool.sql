-- ============================================================
-- Password Generator — Tool Registration
--
-- Purely a registry row. The tool is 100% client-side: no table, no
-- endpoint, and no server-side storage of generated credentials.
-- ============================================================

INSERT IGNORE INTO tools (tool_key, label, description, icon, color, tags, is_enabled, sort_order) VALUES
  ('password', 'Password Generator', 'Generate cryptographically secure passwords, passphrases and PINs with a live strength meter and browser-only history. 100% client-side.', 'bi-shield-lock-fill', '#6366f1', 'Passwords,Entropy,Offline', 1, 11);

-- This migration first shipped with sort_order 10, which `myip` already held, so
-- the two rendered in an arbitrary order together. `tool_key` is the only unique
-- key, which means the INSERT IGNORE above kept the stale row and the fix has
-- to be a separate statement.
--
-- Deliberately narrow: it moves sort_order only, and only off the colliding
-- value. /admin can edit every other column on this row, and the migrations
-- directory is replayed on every container start — a blanket upsert here would
-- quietly revert the admin's changes on the next restart.
UPDATE tools SET sort_order = 11 WHERE tool_key = 'password' AND sort_order = 10;
