<?php

/**
 * @var App\Core\Router $router
 */

use App\Controllers\AuthController;
use App\Controllers\DashboardController;
use App\Controllers\DomainController;
use App\Controllers\InstallController;
use App\Controllers\LogController;
use App\Controllers\NotifyController;
use App\Controllers\ProxyController;
use App\Controllers\ProxyGroupController;
use App\Controllers\SettingController;
use App\Controllers\SubdomainController;
use App\Middleware\AuthMiddleware;

$auth = [fn($req) => AuthMiddleware::handle($req)];

// === 1. 安装向导接口 (未安装允许，已安装阻断) ===
$router->get('/api/v1/install/status',       [InstallController::class, 'status']);
$router->post('/api/v1/install/check-env',   [InstallController::class, 'checkEnv']);
$router->post('/api/v1/install/test-db',     [InstallController::class, 'testDb']);
$router->post('/api/v1/install/database',    [InstallController::class, 'database']);
$router->post('/api/v1/install/admin',       [InstallController::class, 'admin']);
$router->post('/api/v1/install/notify',      [InstallController::class, 'notify']);
$router->post('/api/v1/install/complete',    [InstallController::class, 'complete']);

// === 2. 身份认证与凭据接口 ===
$router->post('/api/v1/auth/captcha', [AuthController::class, 'captcha']);
$router->post('/api/v1/auth/login',   [AuthController::class, 'login']);
$router->get('/api/v1/auth/me',       [AuthController::class, 'me'], $auth);
$router->post('/api/v1/auth/logout',  [AuthController::class, 'logout'], $auth);

// === 3. 综合仪表盘数据 ===
$router->get('/api/v1/dashboard/stats',         [DashboardController::class, 'stats'], $auth);
$router->get('/api/v1/dashboard/chart/trends',  [DashboardController::class, 'trends'], $auth);
$router->get('/api/v1/dashboard/chart/changes', [DashboardController::class, 'changes'], $auth);
$router->get('/api/v1/dashboard/timeline',      [DashboardController::class, 'timeline'], $auth);

// === 4. 资产主域名管理 ===
$router->get('/api/v1/domains',                 [DomainController::class, 'index'], $auth);
$router->post('/api/v1/domains',                [DomainController::class, 'store'], $auth);
$router->put('/api/v1/domains/{id}',            [DomainController::class, 'update'], $auth);
$router->delete('/api/v1/domains/{id}',         [DomainController::class, 'destroy'], $auth);
$router->post('/api/v1/domains/{id}/scan',      [DomainController::class, 'scan'], $auth);
$router->post('/api/v1/domains/{id}/proxy-test',[DomainController::class, 'testProxy'], $auth);
$router->post('/api/v1/domains/{id}/resolve-names', [SubdomainController::class, 'resolveDomainNames'], $auth);
$router->get('/api/v1/subdomains/export',       [DomainController::class, 'exportCsv'], $auth);

// === 5. 子域名资产与名称识别 ===
$router->get('/api/v1/subdomains',                    [SubdomainController::class, 'index'], $auth);
$router->put('/api/v1/subdomains/{id}/alias',         [SubdomainController::class, 'updateAlias'], $auth);
$router->post('/api/v1/subdomains/{id}/resolve-name', [SubdomainController::class, 'resolveSingleName'], $auth);

// === 6. 出口网络代理池与策略组 ===
$router->get('/api/v1/proxies',             [ProxyController::class, 'index'], $auth);
$router->post('/api/v1/proxies',            [ProxyController::class, 'store'], $auth);
$router->put('/api/v1/proxies/{id}',        [ProxyController::class, 'update'], $auth);
$router->delete('/api/v1/proxies/{id}',     [ProxyController::class, 'destroy'], $auth);
$router->post('/api/v1/proxies/import',     [ProxyController::class, 'batchImport'], $auth);
$router->post('/api/v1/proxies/{id}/test',  [ProxyController::class, 'testSingle'], $auth);
$router->get('/api/v1/proxy-stats',         [ProxyController::class, 'stats'], $auth);

$router->get('/api/v1/proxy-groups',        [ProxyGroupController::class, 'index'], $auth);
$router->post('/api/v1/proxy-groups',       [ProxyGroupController::class, 'store'], $auth);
$router->delete('/api/v1/proxy-groups/{id}',[ProxyGroupController::class, 'destroy'], $auth);

// === 7. 多渠道告警通道 ===
$router->get('/api/v1/notify-channels',          [NotifyController::class, 'index'], $auth);
$router->post('/api/v1/notify-channels',         [NotifyController::class, 'store'], $auth);
$router->delete('/api/v1/notify-channels/{id}',  [NotifyController::class, 'destroy'], $auth);
$router->post('/api/v1/notify-channels/{id}/test',[NotifyController::class, 'testChannel'], $auth);

// === 8. 巡检任务与系统运行流水日志 (带分页) ===
$router->get('/api/v1/logs/tasks',  [LogController::class, 'getTasks'], $auth);
$router->get('/api/v1/logs/stages', [LogController::class, 'getStages'], $auth);

// === 9. 系统全局设置与字典 ===
$router->get('/api/v1/settings',            [SettingController::class, 'getSettings'], $auth);
$router->post('/api/v1/settings',           [SettingController::class, 'saveSetting'], $auth);
$router->get('/api/v1/settings/audit-logs', [SettingController::class, 'auditLogs'], $auth);
