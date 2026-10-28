-- SQLite 兼容轻量初始 DDL (含扩展多源与接管检测)
CREATE TABLE IF NOT EXISTS install_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  step TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  user_agent TEXT DEFAULT '',
  status INTEGER DEFAULT 1,
  message TEXT DEFAULT '',
  duration_ms INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  status INTEGER DEFAULT 1,
  failed_login_count INTEGER DEFAULT 0,
  locked_until DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  username TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  user_agent TEXT DEFAULT '',
  status INTEGER DEFAULT 1,
  fail_reason TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS proxy_groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  strategy TEXT DEFAULT 'round-robin',
  fail_strategy TEXT DEFAULT 'failover',
  max_concurrency INTEGER DEFAULT 10,
  rate_limit_minute INTEGER DEFAULT 600,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS proxies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  protocol TEXT DEFAULT 'http',
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  auth_user TEXT,
  auth_pass_encrypted TEXT,
  priority INTEGER DEFAULT 10,
  max_concurrency INTEGER DEFAULT 5,
  rate_limit_per_minute INTEGER DEFAULT 120,
  status INTEGER DEFAULT 1,
  health_status TEXT DEFAULT 'healthy',
  consecutive_fails INTEGER DEFAULT 0,
  last_error TEXT,
  last_check_at DATETIME,
  latency_ms INTEGER DEFAULT 0,
  egress_ip TEXT,
  used_requests_today INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS proxy_group_items (
  group_id INTEGER NOT NULL,
  proxy_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, proxy_id)
);

CREATE TABLE IF NOT EXISTS proxy_health_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proxy_id INTEGER NOT NULL,
  status TEXT NOT NULL,
  latency_ms INTEGER DEFAULT 0,
  egress_ip TEXT,
  error_code TEXT,
  error_message TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS proxy_usage_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proxy_id INTEGER NOT NULL,
  domain_id INTEGER,
  requests_count INTEGER DEFAULT 1,
  fails_count INTEGER DEFAULT 0,
  duration_ms INTEGER DEFAULT 0,
  egress_ip TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notify_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  config TEXT NOT NULL,
  proxy_group_id INTEGER,
  status INTEGER DEFAULT 1,
  silence_start TEXT,
  silence_end TEXT,
  custom_template TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER DEFAULT 1,
  domain TEXT UNIQUE NOT NULL,
  group_name TEXT DEFAULT '默认分组',
  remark TEXT DEFAULT '',
  is_enabled INTEGER DEFAULT 1,
  check_interval TEXT DEFAULT '1h',
  proxy_mode TEXT DEFAULT 'auto',
  proxy_group_id INTEGER,
  proxy_override TEXT,
  enable_axfr INTEGER DEFAULT 0,
  enable_c_segment INTEGER DEFAULT 0,
  enable_wildcard_filter INTEGER DEFAULT 1,
  last_scanned_at DATETIME,
  subdomain_count INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domain_channel (
  domain_id INTEGER NOT NULL,
  channel_id INTEGER NOT NULL,
  PRIMARY KEY (domain_id, channel_id)
);

CREATE TABLE IF NOT EXISTS subdomains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  subdomain TEXT NOT NULL,
  asset_name TEXT DEFAULT '',
  alias_name TEXT DEFAULT NULL,
  asset_name_source TEXT DEFAULT 'hostname',
  asset_name_updated_at DATETIME DEFAULT NULL,
  record_type TEXT DEFAULT 'A',
  record_value TEXT NOT NULL,
  source TEXT DEFAULT 'enum',
  status TEXT DEFAULT 'active',
  takeover_risk INTEGER DEFAULT 0,
  takeover_reason TEXT DEFAULT NULL,
  cname_chain TEXT DEFAULT NULL,
  provenance_sources TEXT DEFAULT NULL,
  first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (domain_id, subdomain, record_type)
);

CREATE TABLE IF NOT EXISTS dns_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  task_id INTEGER,
  snapshot_hash TEXT NOT NULL,
  total_records INTEGER DEFAULT 0,
  snapshot_data TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS change_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  subdomain TEXT NOT NULL,
  asset_name TEXT DEFAULT NULL,
  asset_name_source TEXT DEFAULT NULL,
  provenance_source TEXT DEFAULT 'unknown',
  priority_level TEXT DEFAULT 'normal',
  record_type TEXT NOT NULL,
  change_type TEXT NOT NULL,
  old_value TEXT,
  new_value TEXT,
  is_notified INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notify_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id INTEGER NOT NULL,
  domain_id INTEGER,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  status INTEGER DEFAULT 1,
  retry_count INTEGER DEFAULT 0,
  response_data TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  trigger_type TEXT DEFAULT 'auto',
  status TEXT DEFAULT 'pending',
  proxy_used_id INTEGER,
  discovered_count INTEGER DEFAULT 0,
  changes_count INTEGER DEFAULT 0,
  error_message TEXT,
  started_at DATETIME,
  finished_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_task_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  stage TEXT NOT NULL,
  level TEXT DEFAULT 'info',
  message TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  value TEXT,
  comment TEXT DEFAULT '',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS operation_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  username TEXT NOT NULL,
  module TEXT NOT NULL,
  action TEXT NOT NULL,
  ip TEXT NOT NULL,
  params TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO settings (key, value, comment) VALUES
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
('system_version', '1.2.0', '当前系统发布版本号');
