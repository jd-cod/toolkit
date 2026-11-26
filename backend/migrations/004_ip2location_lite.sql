-- IP2Location LITE local enrichment tables

USE sysadmin_toolkit;

CREATE TABLE IF NOT EXISTS ip2location_db11_ipv4 (
  ip_from BIGINT UNSIGNED NOT NULL,
  ip_to BIGINT UNSIGNED NOT NULL,
  country_code CHAR(2),
  country_name VARCHAR(64),
  region_name VARCHAR(128),
  city_name VARCHAR(128),
  latitude DOUBLE NULL,
  longitude DOUBLE NULL,
  zip_code VARCHAR(30),
  time_zone VARCHAR(16),
  PRIMARY KEY (ip_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ip2location_db11_ipv6 (
  ip_from DECIMAL(39,0) NOT NULL,
  ip_to DECIMAL(39,0) NOT NULL,
  country_code CHAR(2),
  country_name VARCHAR(64),
  region_name VARCHAR(128),
  city_name VARCHAR(128),
  latitude DOUBLE NULL,
  longitude DOUBLE NULL,
  zip_code VARCHAR(30),
  time_zone VARCHAR(16),
  PRIMARY KEY (ip_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ip2location_px7_ipv4 (
  ip_from BIGINT UNSIGNED NOT NULL,
  ip_to BIGINT UNSIGNED NOT NULL,
  proxy_type VARCHAR(3),
  country_code CHAR(2),
  country_name VARCHAR(64),
  region_name VARCHAR(128),
  city_name VARCHAR(128),
  isp VARCHAR(256),
  domain VARCHAR(128),
  usage_type VARCHAR(11),
  asn VARCHAR(16),
  as_name VARCHAR(256),
  PRIMARY KEY (ip_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ip2location_px7_ipv6 (
  ip_from DECIMAL(39,0) NOT NULL,
  ip_to DECIMAL(39,0) NOT NULL,
  proxy_type VARCHAR(3),
  country_code CHAR(2),
  country_name VARCHAR(64),
  region_name VARCHAR(128),
  city_name VARCHAR(128),
  isp VARCHAR(256),
  domain VARCHAR(128),
  usage_type VARCHAR(11),
  asn VARCHAR(16),
  as_name VARCHAR(256),
  PRIMARY KEY (ip_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ip2location_asn_ipv4 (
  ip_from BIGINT UNSIGNED NOT NULL,
  ip_to BIGINT UNSIGNED NOT NULL,
  cidr VARCHAR(43),
  asn VARCHAR(16),
  as_name VARCHAR(256),
  PRIMARY KEY (ip_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ip2location_asn_ipv6 (
  ip_from DECIMAL(39,0) NOT NULL,
  ip_to DECIMAL(39,0) NOT NULL,
  cidr VARCHAR(43),
  asn VARCHAR(16),
  as_name VARCHAR(256),
  PRIMARY KEY (ip_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ip2location_refresh_state (
  state_key VARCHAR(64) NOT NULL PRIMARY KEY,
  state_value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
