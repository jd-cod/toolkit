-- ============================================================
-- What Is My IP — Tool Registration + Share Table
-- ============================================================

-- Add MyIP tool to the tools registry
INSERT IGNORE INTO tools (tool_key, label, description, icon, color, tags, is_enabled, sort_order) VALUES
  ('myip', 'What Is My IP', 'Instantly see your public IP address with geolocation, ISP, ASN, reverse DNS, connection quality, and browser fingerprint. Share or export results.', 'bi-geo-alt-fill', '#3b82f6', 'IP,Geolocation,ISP,ASN,Privacy', 1, 10);

-- MyIP share links table (same pattern as dns_shares / whois_shares)
CREATE TABLE IF NOT EXISTS myip_shares (
    code VARCHAR(20) PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    password_hash VARCHAR(255),
    expires_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checked_at_utc VARCHAR(50) NOT NULL,
    data_json LONGTEXT NOT NULL
) ENGINE=InnoDB;
