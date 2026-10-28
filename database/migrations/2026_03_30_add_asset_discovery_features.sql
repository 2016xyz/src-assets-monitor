-- ========================================================
-- 增量迁移脚本: 扩展资产发现能力与接管检测字段
-- ========================================================

ALTER TABLE `subdomains`
  ADD COLUMN `takeover_risk` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否存在CNAME/云存储桶悬挂接管风险(1存在, 0无)' AFTER `status`,
  ADD COLUMN `takeover_reason` VARCHAR(255) NULL DEFAULT NULL COMMENT '接管风险详细原因' AFTER `takeover_risk`,
  ADD COLUMN `cname_chain` TEXT NULL DEFAULT NULL COMMENT '解析追踪到的CNAME链JSON' AFTER `takeover_reason`,
  ADD COLUMN `provenance_sources` TEXT NULL DEFAULT NULL COMMENT '发现该子域名的所有源渠道JSON' AFTER `cname_chain`;

ALTER TABLE `domains`
  ADD COLUMN `enable_axfr` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否允许执行DNS区域传送AXFR尝试(高敏操作默认0)' AFTER `proxy_override`,
  ADD COLUMN `enable_c_segment` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否开启同C段横向旁站探查(高噪声默认0)' AFTER `enable_axfr`,
  ADD COLUMN `enable_wildcard_filter` TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否启用泛解析自动识别与清洗' AFTER `enable_c_segment`;

ALTER TABLE `change_logs`
  ADD COLUMN `provenance_source` VARCHAR(50) NULL DEFAULT 'unknown' COMMENT '触发该变动的来源渠道' AFTER `asset_name_source`,
  ADD COLUMN `priority_level` VARCHAR(20) NOT NULL DEFAULT 'normal' COMMENT '通知优先级: critical/high/normal/low' AFTER `provenance_source`;

-- 初始配置增补
INSERT INTO `settings` (`key`, `value`, `comment`) VALUES
('github_token', '', 'GitHub API 访问令牌 (用于 GitHub Dorks 代码泄露资产搜寻)'),
('otx_api_key', '', 'AlienVault OTX API Key (被动 DNS 数据源扩展)'),
('fofa_email_key', '{"email":"","key":""}', 'FOFA 网络空间测绘平台凭据 (可选)'),
('securitytrails_key', '', 'SecurityTrails API Key (可选高精度历史DNS)'),
('virustotal_key', '', 'VirusTotal API Key (可选)')
ON DUPLICATE KEY UPDATE `comment` = VALUES(`comment`);
