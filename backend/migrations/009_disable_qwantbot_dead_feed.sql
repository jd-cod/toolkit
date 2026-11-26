-- ============================================================
-- SysAdmin Toolkit — Migration 009: retire the dead QwantBot feed
-- ============================================================
-- `qwantbot` has been in `last_status = 'error'` since its first sync on
-- 2026-09-29, with `total_cidrs = 0`. The feed it points at is gone:
--
--   https://help.qwant.com/wp-content/uploads/sites/latest/qwantbot.json -> HTTP 404
--
-- Checked again on 2026-09-30 while fixing the six lost STATIC_FALLBACKS
-- sources. Every alternative was probed directly and is also dead:
--
--   https://api.qwant.com/v3/bot/qwantbot.json      -> 404
--   https://www.qwant.com/qwantbot.json            -> 404 (serves an HTML error
--                                                      page, not JSON)
--   https://qwant.com/qwantbot.json                -> 404
--   https://help.qwant.com/.../sites/4/bot/...     -> 404
--   https://www.qwant.com/bot                      -> 200, but publishes NO IP
--                                                      ranges and no feed URL;
--                                                      scraping it yields zero
--                                                      CIDR literals
--
-- Qwant's robots.txt does list QwantBot as an allowed agent, so the crawler
-- still exists — the machine-readable list simply is not published anywhere
-- reachable. The only figure found (a /16) came from a search-engine summary
-- and could not be confirmed against any primary source, so it is NOT added
-- here: an unverified range would mark real spoofed QwantBot traffic as
-- "verified genuine", which is the exact failure mode this table exists to
-- prevent.
--
-- Disabling rather than deleting preserves the row, its history, and the
-- ability to re-enable it in one statement if Qwant republishes a feed.
-- Without this the daily sync would keep reporting a 404 for this source
-- forever, and a permanently-red source is noise that trains operators to
-- ignore the error states that matter.
--
-- Effect on classification: QwantBot remains detectable by User-Agent via
-- BOT_PATTERNS in frontend/public/js/bot-detector.js. With the source
-- disabled it is compiled out of verified-bots.json entirely, so
-- verifyBot() takes the `activeSources.length === 0` path and reports
-- `unverified_publisher` — the correct, honest verdict for a publisher with
-- no reachable range list. It is NOT silently treated as verified.
-- ============================================================

USE sysadmin_toolkit;

UPDATE bot_sources
SET is_enabled = 0,
    last_error = 'Feed retired 2026-09-30: upstream 404 and no reachable replacement. Re-enable if Qwant republishes a machine-readable range list.'
WHERE bot_key = 'qwantbot';
