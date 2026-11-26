-- Migration 005: R2 Storage Migration
-- Replace GitHub Gist storage with Cloudflare R2 object storage

-- Modify shares table: remove Gist columns, add R2 columns
-- Note: MySQL doesn't support DROP COLUMN IF EXISTS in single ALTER, so we check first

-- Drop old columns if they exist
SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'shares' AND column_name = 'gist_url');
SET @sqlstmt := IF(@exist > 0, 'ALTER TABLE shares DROP COLUMN gist_url', 'SELECT "Column gist_url does not exist"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'shares' AND column_name = 'customer_gist_url');
SET @sqlstmt := IF(@exist > 0, 'ALTER TABLE shares DROP COLUMN customer_gist_url', 'SELECT "Column customer_gist_url does not exist"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'shares' AND column_name = 'owned_gist_url');
SET @sqlstmt := IF(@exist > 0, 'ALTER TABLE shares DROP COLUMN owned_gist_url', 'SELECT "Column owned_gist_url does not exist"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'shares' AND column_name = 'gist_created_by_us');
SET @sqlstmt := IF(@exist > 0, 'ALTER TABLE shares DROP COLUMN gist_created_by_us', 'SELECT "Column gist_created_by_us does not exist"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add new R2 columns if they don't exist
SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'shares' AND column_name = 'r2_key');
SET @sqlstmt := IF(@exist = 0, 'ALTER TABLE shares ADD COLUMN r2_key VARCHAR(255) DEFAULT NULL AFTER password_hash', 'SELECT "Column r2_key already exists"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'shares' AND column_name = 'source_url');
SET @sqlstmt := IF(@exist = 0, 'ALTER TABLE shares ADD COLUMN source_url TEXT DEFAULT NULL AFTER r2_key', 'SELECT "Column source_url already exists"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'shares' AND column_name = 'r2_uploaded_at');
SET @sqlstmt := IF(@exist = 0, 'ALTER TABLE shares ADD COLUMN r2_uploaded_at DATETIME DEFAULT NULL AFTER source_url', 'SELECT "Column r2_uploaded_at already exists"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add indexes if they don't exist
SET @exist := (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'shares' AND index_name = 'idx_r2_key');
SET @sqlstmt := IF(@exist = 0, 'ALTER TABLE shares ADD INDEX idx_r2_key (r2_key)', 'SELECT "Index idx_r2_key already exists"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @exist := (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'shares' AND index_name = 'idx_expires_at');
SET @sqlstmt := IF(@exist = 0, 'ALTER TABLE shares ADD INDEX idx_expires_at (expires_at)', 'SELECT "Index idx_expires_at already exists"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Note: dns_shares, whois_shares, myip_shares, asn_shares store their data
-- in the data_json column (not as separate log files), so they don't need r2_key columns.
-- They continue to work as-is with JSON storage in MySQL.

