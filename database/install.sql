-- ========================================================
-- SRC 资产检测站 (SRC Assets Monitor) - 生产数据库初始架构 (含完整扩展源模块)
-- ========================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

CREATE TABLE IF NOT EXISTS `install_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `step` VARCHAR(50) NOT NULL,
  `client_ip` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) NOT NULL DEFAULT '',
  `status` TINYINT(1) NOT NULL DEFAULT 1,
  `message` VARCHAR(500) NOT NULL DEFAULT '',
  `duration_ms` INT UNSIGNED NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `users` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(50) NOT NULL,
  `email` VARCHAR(100) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `role` VARCHAR(20) NOT NULL DEFAULT 'user',
  `status` TINYINT(1) NOT NULL DEFAULT 1,
  `failed_login_count` TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `locked_until` TIMESTAMP NULL DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_username` (`username`),
  UNIQUE KEY `uk_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `login_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NULL,
  `username` VARCHAR(50) NOT NULL,
  `client_ip` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) NOT NULL DEFAULT '',
  `status` TINYINT(1) NOT NULL DEFAULT 1,
  `fail_reason` VARCHAR(255) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `proxy_groups` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `description` VARCHAR(255) NULL DEFAULT '',
  `strategy` VARCHAR(30) NOT NULL DEFAULT 'round-robin',
  `fail_strategy` VARCHAR(30) NOT NULL DEFAULT 'failover',
  `max_concurrency` INT UNSIGNED NOT NULL DEFAULT 10,
  `rate_limit_minute` INT UNSIGNED NOT NULL DEFAULT 600,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `proxies` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `protocol` VARCHAR(20) NOT NULL DEFAULT 'http',
  `host` VARCHAR(255) NOT NULL,
  `port` INT UNSIGNED NOT NULL,
  `auth_user` VARCHAR(100) NULL,
  `auth_pass_encrypted` TEXT NULL,
  `priority` INT NOT NULL DEFAULT 10,
  `max_concurrency` INT UNSIGNED NOT NULL DEFAULT 5,
  `rate_limit_per_minute` INT UNSIGNED NOT NULL DEFAULT 120,
  `status` TINYINT(1) NOT NULL DEFAULT 1,
  `health_status` VARCHAR(20) NOT NULL DEFAULT 'healthy',
  `consecutive_fails` INT UNSIGNED NOT NULL DEFAULT 0,
  `last_error` VARCHAR(255) NULL,
  `last_check_at` TIMESTAMP NULL,
  `latency_ms` INT UNSIGNED NOT NULL DEFAULT 0,
  `egress_ip` VARCHAR(45) NULL,
  `used_requests_today` INT UNSIGNED NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `proxy_group_items` (
  `group_id` BIGINT UNSIGNED NOT NULL,
  `proxy_id` BIGINT UNSIGNED NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`group_id`, `proxy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `proxy_health_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `proxy_id` BIGINT UNSIGNED NOT NULL,
  `status` VARCHAR(20) NOT NULL,
  `latency_ms` INT UNSIGNED NOT NULL DEFAULT 0,
  `egress_ip` VARCHAR(45) NULL,
  `error_code` VARCHAR(50) NULL,
  `error_message` VARCHAR(255) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `proxy_usage_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `proxy_id` BIGINT UNSIGNED NOT NULL,
  `domain_id` BIGINT UNSIGNED NULL,
  `requests_count` INT UNSIGNED NOT NULL DEFAULT 1,
  `fails_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `duration_ms` INT UNSIGNED NOT NULL DEFAULT 0,
  `egress_ip` VARCHAR(45) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `notify_channels` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `type` VARCHAR(30) NOT NULL,
  `config` JSON NOT NULL,
  `proxy_group_id` BIGINT UNSIGNED NULL,
  `status` TINYINT(1) NOT NULL DEFAULT 1,
  `silence_start` TIME NULL,
  `silence_end` TIME NULL,
  `custom_template` TEXT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `domains` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL DEFAULT 1,
  `domain` VARCHAR(255) NOT NULL,
  `group_name` VARCHAR(50) NOT NULL DEFAULT '默认分组',
  `remark` VARCHAR(255) NULL DEFAULT '',
  `is_enabled` TINYINT(1) NOT NULL DEFAULT 1,
  `check_interval` VARCHAR(20) NOT NULL DEFAULT '1h',
  `proxy_mode` VARCHAR(20) NOT NULL DEFAULT 'auto',
  `proxy_group_id` BIGINT UNSIGNED NULL,
  `proxy_override` JSON NULL,
  `enable_axfr` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否开启域传送AXFR探测',
  `enable_c_segment` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否开启同C段横向旁站探查',
  `enable_wildcard_filter` TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否启用泛解析自动识别与清洗',
  `last_scanned_at` TIMESTAMP NULL,
  `subdomain_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_domain` (`domain`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `domain_channel` (
  `domain_id` BIGINT UNSIGNED NOT NULL,
  `channel_id` BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (`domain_id`, `channel_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `subdomains` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `domain_id` BIGINT UNSIGNED NOT NULL,
  `subdomain` VARCHAR(255) NOT NULL,
  `asset_name` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '资产名称',
  `alias_name` VARCHAR(255) NULL DEFAULT NULL COMMENT '用户自定义别名',
  `asset_name_source` ENUM('alias','http_title','http_server','cname','ptr','hostname') NOT NULL DEFAULT 'hostname' COMMENT '名称来源渠道',
  `asset_name_updated_at` DATETIME NULL DEFAULT NULL COMMENT '最近一次名称解析时间',
  `record_type` VARCHAR(10) NOT NULL DEFAULT 'A',
  `record_value` TEXT NOT NULL,
  `source` VARCHAR(30) NOT NULL DEFAULT 'enum',
  `status` VARCHAR(20) NOT NULL DEFAULT 'active',
  `takeover_risk` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否存在接管风险',
  `takeover_reason` VARCHAR(255) NULL DEFAULT NULL COMMENT '接管风险原因',
  `cname_chain` TEXT NULL DEFAULT NULL COMMENT 'CNAME链JSON',
  `provenance_sources` TEXT NULL DEFAULT NULL COMMENT '发现源列表JSON',
  `first_seen_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_seen_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sub_type` (`domain_id`, `subdomain`, `record_type`),
  INDEX `idx_sub_asset_name` (`asset_name`),
  INDEX `idx_sub_domain_str` (`subdomain`),
  INDEX `idx_takeover` (`takeover_risk`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `dns_snapshots` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `domain_id` BIGINT UNSIGNED NOT NULL,
  `task_id` BIGINT UNSIGNED NULL,
  `snapshot_hash` CHAR(64) NOT NULL,
  `total_records` INT UNSIGNED NOT NULL DEFAULT 0,
  `snapshot_data` LONGTEXT NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `change_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `domain_id` BIGINT UNSIGNED NOT NULL,
  `subdomain` VARCHAR(255) NOT NULL,
  `asset_name` VARCHAR(255) NULL DEFAULT NULL,
  `asset_name_source` VARCHAR(20) NULL DEFAULT NULL,
  `provenance_source` VARCHAR(50) NULL DEFAULT 'unknown',
  `priority_level` VARCHAR(20) NOT NULL DEFAULT 'normal',
  `record_type` VARCHAR(10) NOT NULL,
  `change_type` VARCHAR(30) NOT NULL,
  `old_value` TEXT NULL,
  `new_value` TEXT NULL,
  `is_notified` TINYINT(1) NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX `idx_cl_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `notify_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `channel_id` BIGINT UNSIGNED NOT NULL,
  `domain_id` BIGINT UNSIGNED NULL,
  `title` VARCHAR(255) NOT NULL,
  `content` TEXT NOT NULL,
  `status` TINYINT(1) NOT NULL DEFAULT 1,
  `retry_count` TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `response_data` TEXT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `scan_tasks` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `domain_id` BIGINT UNSIGNED NOT NULL,
  `trigger_type` VARCHAR(20) NOT NULL DEFAULT 'auto',
  `status` VARCHAR(20) NOT NULL DEFAULT 'pending',
  `proxy_used_id` BIGINT UNSIGNED NULL,
  `discovered_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `changes_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `error_message` VARCHAR(500) NULL,
  `started_at` TIMESTAMP NULL,
  `finished_at` TIMESTAMP NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `scan_task_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `task_id` BIGINT UNSIGNED NOT NULL,
  `stage` VARCHAR(30) NOT NULL,
  `level` VARCHAR(10) NOT NULL DEFAULT 'info',
  `message` VARCHAR(1000) NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `settings` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `key` VARCHAR(50) NOT NULL,
  `value` LONGTEXT NULL,
  `comment` VARCHAR(255) NULL DEFAULT '',
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_setting_key` (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `operation_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `username` VARCHAR(50) NOT NULL,
  `module` VARCHAR(50) NOT NULL,
  `action` VARCHAR(50) NOT NULL,
  `ip` VARCHAR(45) NOT NULL,
  `params` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `settings` (`key`, `value`, `comment`) VALUES
('installed', '0', '系统是否已完成安装引导 (0未装, 1已装)'),
('install_time', NULL, '系统首次安装初始化完成时间戳'),
('doh_endpoints', '["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]', '默认启用的公共 DoH 服务端池'),
('global_proxy_policy', '{"enable": false, "default_group_id": null, "fallback_direct": true, "max_concurrency": 10, "jitter_ms": 300}', '全局网络出站代理策略'),
('dictionary_subdomains', '["www","api","mail","oa","vpn","dev","test","admin","portal","git","jenkins","auth","sso","internal","wiki","stage","ops","monitor","grafana","k8s"]', '系统默认内置子域名字典'),
('enable_asset_name_http_probe', '1', '是否开启资产名称 HTTP(S) 网页标题探针识别 (1开启, 0关闭仅用低成本模式)'),
('github_token', '', 'GitHub API 访问令牌 (用于 GitHub Dorks 代码泄露资产搜寻)'),
('otx_api_key', '', 'AlienVault OTX API Key (被动 DNS 数据源扩展)'),
('fofa_email_key', '{"email":"","key":""}', 'FOFA 网络空间测绘平台凭据 (可选)'),
('securitytrails_key', '', 'SecurityTrails API Key (可选高精度历史DNS)'),
('virustotal_key', '', 'VirusTotal API Key (可选)'),
('system_version', '1.2.0', '当前系统发布版本号')
ON DUPLICATE KEY UPDATE `comment`=VALUES(`comment`);

SET FOREIGN_KEY_CHECKS = 1;
