USE sysadmin_toolkit;

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

INSERT IGNORE INTO tools (tool_key, label, description, icon, color, tags, is_enabled, sort_order) VALUES
  ('whois', 'WHOIS Lookup', 'Inspect domain registration metadata, statuses, registrar details, nameservers, DNSSEC, and expiry risk signals.', 'bi-person-vcard-fill', '#38bdf8', 'WHOIS,Domains,Registrar,Expiry', 1, 9);
