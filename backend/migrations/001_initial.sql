-- ============================================================
-- SysAdmin Toolkit — MySQL 8.4 Schema
-- Migrated from Cloudflare D1 (SQLite)
-- ============================================================

CREATE DATABASE IF NOT EXISTS sysadmin_toolkit
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE sysadmin_toolkit;

-- 1. Admin Users
CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. Site Settings (key-value)
CREATE TABLE IF NOT EXISTS site_settings (
    `key` VARCHAR(100) PRIMARY KEY,
    `value` TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 3. Pages (CMS)
CREATE TABLE IF NOT EXISTS pages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    slug VARCHAR(255) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    content LONGTEXT NOT NULL DEFAULT (''),
    meta_title VARCHAR(500) DEFAULT '',
    meta_description TEXT DEFAULT (''),
    is_published TINYINT DEFAULT 1,
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 4. Navigation Menus
CREATE TABLE IF NOT EXISTS menus (
    id INT AUTO_INCREMENT PRIMARY KEY,
    location VARCHAR(50) NOT NULL,
    label VARCHAR(255) NOT NULL,
    url VARCHAR(500) NOT NULL,
    icon VARCHAR(100) DEFAULT '',
    sort_order INT DEFAULT 0,
    is_visible TINYINT DEFAULT 1,
    open_in_new_tab TINYINT DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 5. Tools Configuration
CREATE TABLE IF NOT EXISTS tools (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tool_key VARCHAR(50) UNIQUE NOT NULL,
    label VARCHAR(255) NOT NULL,
    description TEXT DEFAULT (''),
    icon VARCHAR(100) DEFAULT '',
    color VARCHAR(20) DEFAULT '#6366f1',
    tags VARCHAR(500) DEFAULT '',
    is_enabled TINYINT DEFAULT 1,
    sort_order INT DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 6. Footer Settings
CREATE TABLE IF NOT EXISTS footer_settings (
    `key` VARCHAR(100) PRIMARY KEY,
    `value` TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 7. Activity Log
CREATE TABLE IF NOT EXISTS admin_activity_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    details TEXT DEFAULT (''),
    admin_username VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created (created_at)
) ENGINE=InnoDB;

-- 8. Shares (Nginx log analysis shares via Cloudflare R2)
--
-- Declares the R2 columns directly rather than the GitHub Gist columns this
-- table used to carry. The old shape required a follow-up migration to drop
-- gist_url / customer_gist_url / owned_gist_url / gist_created_by_us, and that
-- ordering was fragile: on a fresh database 001 created the gist columns and
-- 002 re-added them with AFTER gist_url, so 002 failed with
-- "Unknown column 'gist_url'" on every single migration run.
--
-- Existing databases are unaffected — CREATE TABLE IF NOT EXISTS is a no-op
-- there, and 005_r2_storage.sql still drops the legacy columns for them.
CREATE TABLE IF NOT EXISTS shares (
    code VARCHAR(20) PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    password_hash VARCHAR(255),
    r2_key VARCHAR(255),
    source_url TEXT,
    r2_uploaded_at DATETIME NULL DEFAULT NULL,
    expires_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_r2_key (r2_key),
    KEY idx_expires_at (expires_at)
) ENGINE=InnoDB;

-- 9. DNS Shares (DNS snapshot shares)
CREATE TABLE IF NOT EXISTS dns_shares (
    code VARCHAR(20) PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    domain VARCHAR(253) NOT NULL,
    password_hash VARCHAR(255),
    expires_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checked_at_utc VARCHAR(50) NOT NULL,
    data_json LONGTEXT NOT NULL
) ENGINE=InnoDB;

-- 10. WHOIS Shares (WHOIS snapshot shares)
CREATE TABLE IF NOT EXISTS whois_shares (
    code VARCHAR(20) PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    domain VARCHAR(253) NOT NULL,
    password_hash VARCHAR(255),
    expires_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checked_at_utc VARCHAR(50) NOT NULL,
    data_json LONGTEXT NOT NULL
) ENGINE=InnoDB;

-- ============================================================
-- SEED DATA
-- ============================================================

INSERT IGNORE INTO site_settings (`key`, `value`) VALUES
    ('site_title', 'SysAdmin Toolkit'),
    ('site_description', 'Essential security & network tools for Linux system administrators.'),
    ('site_tagline', 'Network & Security Suite'),
    ('home_hero_title', 'SysAdmin Toolkit'),
    ('home_hero_subtitle', 'Fast, client-first, and privacy-friendly.'),
    ('meta_description', 'Traffic Log Analyzer, ASN Lookup, and IP Intelligence tools. Fast, local-first, privacy-friendly SysAdmin toolkit.'),
    ('favicon_emoji', '🛡️'),
    ('brand_icon', 'bi-shield-lock-fill'),
    ('version_badge', 'v3.0'),
    ('maintenance_mode', '0'),
    ('maintenance_message', 'We are currently performing scheduled maintenance. Please check back soon.'),
    ('announcement_enabled', '0'),
    ('announcement_text', ''),
    ('announcement_type', 'info'),
    ('announcement_dismissible', '1'),
    ('custom_css', ''),
    ('analytics_script', ''),
    ('invite_only_enabled', '0'),
    ('invite_only_title', 'Invite Only'),
    ('invite_only_message', 'This site is currently invite-only. If you believe you should have access, please contact the administrator.'),
    ('invite_only_whitelist_ips', '');

INSERT IGNORE INTO tools (tool_key, label, description, icon, color, tags, is_enabled, sort_order) VALUES
    ('nginx', 'Traffic Analyzer', 'Paste web access logs and get instant security insights — country & ASN breakdown, top attacking IPs, bot detection, and visual charts. 100% client-side.', 'bi-shield-lock-fill', '#6366f1', 'Traffic,GeoIP,Charts,Offline', 1, 1),
    ('asn', 'ASN to IPs Converter', 'Enter any ASN number to discover all IPv4 and IPv6 prefixes announced by that network. Export results with one click.', 'bi-diagram-3-fill', '#06b6d4', 'BGP,Prefixes,RIPEstat', 1, 2),
    ('abuse', 'IP Info & Risk Lookup', 'Look up IP addresses for reverse DNS (PTR), network type, country, ISP, security risk factors, and AbuseIPDB scores.', 'bi-info-circle-fill', '#f59e0b', 'GeoIP,rDNS,IPInfo,Abuse', 1, 3),
    ('subnet', 'Subnet / CIDR Calculator', 'Calculate network range, usable hosts, broadcast address, and AWS-reserved IP impact for IPv4 CIDR blocks.', 'bi-hdd-network-fill', '#10b981', 'Networking,CIDR,AWS', 1, 4),
    ('cron', 'Crontab Builder', 'Build, validate, and explain cron expressions with presets and upcoming execution previews.', 'bi-clock-fill', '#a855f7', 'Scheduling,Cron,Validation', 1, 5),
    ('dns', 'DNS Lookup', 'Query A, AAAA, CNAME, MX, TXT, NS, SOA, and CAA records across selectable resolvers.', 'bi-globe2', '#22d3ee', 'DNS,Lookup,Resolvers', 1, 6),
    ('ssl', 'SSL Certificate Checker', 'Inspect certificate expiry, issuer chain, SANs, protocol details, and hostname trust signals.', 'bi-shield-lock-fill', '#ef4444', 'TLS,Certificates,Security', 1, 7),
    ('chmod', 'chmod Calculator', 'Convert between octal and symbolic permissions with an interactive Linux permission matrix.', 'bi-key-fill', '#fbbf24', 'Linux,Permissions,Calculator', 1, 8),
    ('whois', 'WHOIS Lookup', 'Inspect domain registration metadata, statuses, registrar details, nameservers, DNSSEC, and expiry risk signals.', 'bi-person-vcard-fill', '#38bdf8', 'WHOIS,Domains,Registrar,Expiry', 1, 9);

INSERT IGNORE INTO footer_settings (`key`, `value`) VALUES
    ('footer_text', 'SysAdmin Toolkit · GeoIP by MaxMind · All processing runs in your browser'),
    ('show_powered_by', '1'),
    ('copyright_text', ''),
    ('social_github', ''),
    ('social_twitter', ''),
    ('social_linkedin', ''),
    ('footer_links_enabled', '1');

INSERT IGNORE INTO menus (location, label, url, icon, sort_order, is_visible) VALUES
    ('header', 'Traffic Analyzer', '/nginx', 'bi-shield-lock', 1, 1),
    ('header', 'ASN', '/asn', 'bi-diagram-3', 2, 1),
    ('header', 'IP Info', '/abuse', 'bi-info-circle', 3, 1);
