-- ============================================================
-- SysAdmin Toolkit — Migration 013: monitoring
-- ============================================================
-- Monitors re-run a check on a schedule and alert when its state changes.
-- Until customer accounts exist they belong to the admin and are managed in
-- /admin (see docs/TOOLS_ROADMAP.md, "Monitoring").
--
--   monitors        one row per watched target, with its current state
--   monitor_events  state changes, newest first in the admin view
--   alert_channels  where alerts are sent (webhook, Slack-style webhook, email)
-- ============================================================

USE sysadmin_toolkit;

CREATE TABLE IF NOT EXISTS monitors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    -- ssl_expiry | domain_expiry | blacklist | dns_record | http | tcp | heartbeat
    type VARCHAR(30) NOT NULL,
    target VARCHAR(500) NOT NULL DEFAULT '',
    config_json TEXT,
    interval_minutes INT NOT NULL DEFAULT 60,
    is_enabled TINYINT NOT NULL DEFAULT 1,
    -- pending | ok | warn | down
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    status_message VARCHAR(1000) NOT NULL DEFAULT '',
    status_since TIMESTAMP NULL DEFAULT NULL,
    last_checked_at TIMESTAMP NULL DEFAULT NULL,
    next_check_at TIMESTAMP NULL DEFAULT NULL,
    last_result_json MEDIUMTEXT,
    consecutive_failures INT NOT NULL DEFAULT 0,
    -- heartbeat monitors only: the secret in the ping URL, and when it was last called
    heartbeat_token VARCHAR(64) NULL DEFAULT NULL,
    last_ping_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_heartbeat_token (heartbeat_token),
    KEY idx_due (is_enabled, next_check_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS monitor_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    monitor_id INT NOT NULL,
    status VARCHAR(20) NOT NULL,
    previous_status VARCHAR(20) NOT NULL DEFAULT '',
    message VARCHAR(1000) NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_monitor_time (monitor_id, created_at),
    CONSTRAINT fk_monitor_events_monitor FOREIGN KEY (monitor_id) REFERENCES monitors (id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alert_channels (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    -- webhook | slack | email
    type VARCHAR(20) NOT NULL,
    -- URL for webhook and slack, address for email
    target VARCHAR(1000) NOT NULL,
    is_enabled TINYINT NOT NULL DEFAULT 1,
    last_status VARCHAR(20) NOT NULL DEFAULT '',
    last_error VARCHAR(500) NOT NULL DEFAULT '',
    last_sent_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
