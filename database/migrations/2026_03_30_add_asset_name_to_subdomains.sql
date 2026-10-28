-- ========================================================
-- 增量迁移脚本: 资产名称记录与来源追踪
-- ========================================================

-- 1. subdomains 表新增字段与索引
ALTER TABLE `subdomains` 
  ADD COLUMN `asset_name` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '资产名称' AFTER `subdomain`,
  ADD COLUMN `alias_name` VARCHAR(255) NULL DEFAULT NULL COMMENT '用户自定义别名' AFTER `asset_name`,
  ADD COLUMN `asset_name_source` ENUM('alias','http_title','http_server','cname','ptr','hostname') NOT NULL DEFAULT 'hostname' COMMENT '名称来源渠道' AFTER `alias_name`,
  ADD COLUMN `asset_name_updated_at` DATETIME NULL DEFAULT NULL COMMENT '最近一次名称解析时间' AFTER `asset_name_source`;

ALTER TABLE `subdomains` ADD INDEX `idx_sub_asset_name` (`asset_name`);

-- 2. change_logs 表新增时刻快照字段与索引
ALTER TABLE `change_logs` 
  ADD COLUMN `asset_name` VARCHAR(255) NULL DEFAULT NULL COMMENT '变更时刻资产名称快照' AFTER `subdomain`,
  ADD COLUMN `asset_name_source` VARCHAR(20) NULL DEFAULT NULL COMMENT '变更时刻名称来源快照' AFTER `asset_name`;

-- 3. 系统配置新增：HTTP 探测名称识别开关 (默认 1 启用)
INSERT INTO `settings` (`key`, `value`, `comment`) VALUES
('enable_asset_name_http_probe', '1', '是否开启资产名称 HTTP(S) 网页标题探针识别 (1开启, 0关闭仅用低成本模式)')
ON DUPLICATE KEY UPDATE `comment` = VALUES(`comment`);
