-- ============================================================
-- SysAdmin Toolkit — Migration 010: Tool & Page SEO enhancements
-- ============================================================
-- Adds explicit SEO meta overrides and search indexing controls:
-- - `tools`: `meta_title`, `meta_description`, `seo_noindex`
-- - `pages`: `seo_noindex`
-- ============================================================

USE sysadmin_toolkit;

-- 1. Tools SEO fields
SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'tools' AND column_name = 'meta_title');
SET @sqlstmt := IF(@exist = 0, 'ALTER TABLE tools ADD COLUMN meta_title VARCHAR(500) DEFAULT \'\' AFTER tags', 'SELECT "Column meta_title already exists in tools"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'tools' AND column_name = 'meta_description');
SET @sqlstmt := IF(@exist = 0, 'ALTER TABLE tools ADD COLUMN meta_description TEXT DEFAULT (\'\') AFTER meta_title', 'SELECT "Column meta_description already exists in tools"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'tools' AND column_name = 'seo_noindex');
SET @sqlstmt := IF(@exist = 0, 'ALTER TABLE tools ADD COLUMN seo_noindex TINYINT DEFAULT 0 AFTER meta_description', 'SELECT "Column seo_noindex already exists in tools"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 2. Pages SEO noindex control
SET @exist := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'pages' AND column_name = 'seo_noindex');
SET @sqlstmt := IF(@exist = 0, 'ALTER TABLE pages ADD COLUMN seo_noindex TINYINT DEFAULT 0 AFTER meta_description', 'SELECT "Column seo_noindex already exists in pages"');
PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
