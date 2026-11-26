-- ============================================================
-- SysAdmin Toolkit — Migration 008: Anthropic (ClaudeBot) IP Source
-- ============================================================
-- ClaudeBot was detectable by User-Agent (see frontend/public/js/bot-detector.js)
-- but had no entry in bot_sources, so every ClaudeBot request was classified
-- `unverified_publisher` and an impersonator could not be told apart from the
-- real crawler.
--
-- Feed: https://claude.com/crawling/bots.json
--   Linked from Anthropic's crawler documentation with the wording "If a crawler
--   has a source IP address on this list, it indicates that the crawler is
--   coming from Anthropic." The list is a `{"creationTime": ..., "prefixes":
--   [{"ipv4Prefix": ...}]}` document, which is exactly the `json_prefixes` shape
--   parseFeedContent() already understands.
--
-- Note: Anthropic does not scope this list per-crawler — it covers Anthropic
-- crawler egress generally (ClaudeBot, Claude-User, Claude-SearchBot), so the
-- ranges deliberately verify the publisher rather than one specific agent.
-- Format is plain IPv4; there is currently no IPv6 range in the feed.
-- ============================================================

USE sysadmin_toolkit;

INSERT IGNORE INTO bot_sources (bot_key, display_name, group_name, feed_url, format, is_enabled) VALUES
('claudebot', 'ClaudeBot', 'Anthropic', 'https://claude.com/crawling/bots.json', 'json_prefixes', 1);
