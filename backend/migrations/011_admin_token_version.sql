-- ============================================================
-- SysAdmin Toolkit — Migration 011: Admin session revocation
-- ============================================================
-- Adds `admin_users.token_version`. Every admin JWT carries the version it
-- was issued under, and logout / password change increment it, so tokens
-- issued earlier stop being accepted instead of staying valid for 72 hours.
-- Existing rows default to 0, which is also what tokens issued before this
-- migration are treated as, so nobody is signed out by applying it.
-- ============================================================

USE sysadmin_toolkit;

SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'admin_users' AND column_name = 'token_version');
SET @sqlstmt := IF(@exist = 0, 'ALTER TABLE admin_users ADD COLUMN token_version INT NOT NULL DEFAULT 0 AFTER password_hash', 'SELECT "Column token_version already exists in admin_users"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
