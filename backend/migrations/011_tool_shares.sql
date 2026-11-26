-- ============================================================
-- SysAdmin Toolkit — Migration 011: Unified snapshot shares
-- ============================================================
-- Every tool that shares a JSON snapshot of its result now stores it in one
-- table, keyed by tool, instead of one table per tool. Rows from the four
-- per-tool tables are moved across so existing /s/<code> links keep working.
--
-- The rows are moved, not copied: once a row is in tool_shares it is removed
-- from its old table. That keeps a replay of this file from bringing back a
-- share an admin has since deleted, and it means an expired snapshot is not
-- left behind in a table nothing cleans up. The old tables are left in place,
-- empty. Traffic Analyzer shares stay in `shares`; they point at R2 objects.
-- ============================================================

USE sysadmin_toolkit;

CREATE TABLE IF NOT EXISTS tool_shares (
    code VARCHAR(20) PRIMARY KEY,
    tool_key VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    subject VARCHAR(255) NOT NULL DEFAULT '',
    password_hash VARCHAR(255),
    expires_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checked_at_utc VARCHAR(50) NOT NULL,
    data_json LONGTEXT NOT NULL,
    KEY idx_tool_key (tool_key),
    KEY idx_expires_at (expires_at),
    KEY idx_created_at (created_at)
) ENGINE=InnoDB;

INSERT IGNORE INTO tool_shares (code, tool_key, title, subject, password_hash, expires_at, created_at, checked_at_utc, data_json)
SELECT code, 'dns', title, domain, password_hash, expires_at, created_at, checked_at_utc, data_json FROM dns_shares;
DELETE s FROM dns_shares s JOIN tool_shares t ON t.code = s.code AND t.tool_key = 'dns';

INSERT IGNORE INTO tool_shares (code, tool_key, title, subject, password_hash, expires_at, created_at, checked_at_utc, data_json)
SELECT code, 'whois', title, domain, password_hash, expires_at, created_at, checked_at_utc, data_json FROM whois_shares;
DELETE s FROM whois_shares s JOIN tool_shares t ON t.code = s.code AND t.tool_key = 'whois';

INSERT IGNORE INTO tool_shares (code, tool_key, title, subject, password_hash, expires_at, created_at, checked_at_utc, data_json)
SELECT code, 'myip', title, ip, password_hash, expires_at, created_at, checked_at_utc, data_json FROM myip_shares;
DELETE s FROM myip_shares s JOIN tool_shares t ON t.code = s.code AND t.tool_key = 'myip';

INSERT IGNORE INTO tool_shares (code, tool_key, title, subject, password_hash, expires_at, created_at, checked_at_utc, data_json)
SELECT code, 'asn', title, asn, password_hash, expires_at, created_at, checked_at_utc, data_json FROM asn_shares;
DELETE s FROM asn_shares s JOIN tool_shares t ON t.code = s.code AND t.tool_key = 'asn';
