-- ============================================================
-- SysAdmin Toolkit — Migration 006: Bot IP Sources Table
-- ============================================================

USE sysadmin_toolkit;

CREATE TABLE IF NOT EXISTS bot_sources (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bot_key VARCHAR(64) NOT NULL UNIQUE,
    display_name VARCHAR(128) NOT NULL,
    group_name VARCHAR(64) DEFAULT NULL,
    feed_url VARCHAR(512) NOT NULL,
    format ENUM('json_prefixes', 'json_synctoken', 'plain_text') NOT NULL DEFAULT 'json_prefixes',
    is_enabled TINYINT(1) NOT NULL DEFAULT 1,
    last_synced_at DATETIME DEFAULT NULL,
    last_status ENUM('ok', 'error', 'pending') DEFAULT 'pending',
    last_error TEXT DEFAULT NULL,
    total_cidrs INT NOT NULL DEFAULT 0,
    cidrs_json LONGTEXT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Seed Default Official Bot IP Feeds
INSERT IGNORE INTO bot_sources (bot_key, display_name, group_name, feed_url, format, is_enabled) VALUES
('googlebot', 'Googlebot', 'Google', 'https://developers.google.com/search/apis/ipranges/googlebot.json', 'json_prefixes', 1),
('google_other', 'Google Other', 'Google', 'https://developers.google.com/search/apis/ipranges/special-crawlers.json', 'json_prefixes', 1),
('google_fetchers', 'Google Fetchers', 'Google', 'https://developers.google.com/search/apis/ipranges/user-triggered-fetchers.json', 'json_prefixes', 1),
('bingbot', 'Bingbot', 'Microsoft', 'https://www.bing.com/toolbox/bingbot.json', 'json_prefixes', 1),
('gptbot', 'GPTBot', 'OpenAI', 'https://openai.com/gptbot.json', 'json_prefixes', 1),
('oai_searchbot', 'OAI-SearchBot', 'OpenAI', 'https://openai.com/searchbot.json', 'json_prefixes', 1),
('chatgpt_user', 'ChatGPT-User', 'OpenAI', 'https://openai.com/chatgpt-user.json', 'json_prefixes', 1),
('duckduckbot', 'DuckDuckBot', 'DuckDuckGo', 'https://duckduckgo.com/duckduckbot.json', 'json_prefixes', 1),
('duckassistbot', 'DuckAssistBot', 'DuckDuckGo', 'https://duckduckgo.com/duckassistbot.json', 'json_prefixes', 1),
('ahrefsbot', 'AhrefsBot', 'Ahrefs', 'https://api.ahrefs.com/v3/public/crawler-ip-ranges', 'json_prefixes', 1),
('ccbot', 'Common Crawl (CCBot)', 'Common Crawl', 'https://index.commoncrawl.org/ccbot.json', 'json_prefixes', 1),
('perplexity', 'PerplexityBot', 'Perplexity AI', 'https://www.perplexity.ai/perplexitybot.json', 'json_prefixes', 1),
('amazonbot', 'Amazonbot', 'Amazon', 'https://developer.amazon.com/amazonbot/searchbot-ip-addresses/', 'plain_text', 1),
('yandexbot', 'YandexBot', 'Yandex', 'https://yandex.com/ips', 'plain_text', 1),
('mojeekbot', 'MojeekBot', 'Mojeek', 'https://www.mojeek.com/mojeekbot.json', 'json_prefixes', 1),
('qwantbot', 'QwantBot', 'Qwant', 'https://help.qwant.com/wp-content/uploads/sites/latest/qwantbot.json', 'json_prefixes', 1);
