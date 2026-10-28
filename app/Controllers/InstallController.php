<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use App\Middleware\EnsureSystemInstalled;
use App\Services\InstallService;
use PDO;

class InstallController
{
    private InstallService $installService;

    public function __construct()
    {
        $this->installService = new InstallService();
    }

    public function status(Request $request): void
    {
        $installed = EnsureSystemInstalled::check();
        if ($installed) {
            Response::json(['installed' => true], 0, '系统已安装');
        }

        $token = $this->installService->generateInstallToken($request->ip());
        Response::json([
            'installed'     => false,
            'install_token' => $token
        ], 0, '系统待安装');
    }

    public function checkEnv(Request $request): void
    {
        $this->guardToken($request);
        $res = $this->installService->checkEnvironment();
        Response::json($res);
    }

    public function testDb(Request $request): void
    {
        $this->guardToken($request);
        $body = $request->input();
        $host = $body['host'] ?? '127.0.0.1';
        $port = (int)($body['port'] ?? 3306);
        $user = $body['username'] ?? 'root';
        $pass = $body['password'] ?? '';

        try {
            if (!extension_loaded('pdo_mysql')) {
                Response::json(['connected' => true, 'note' => '环境未检测到 pdo_mysql，将使用内置 SQLite 兼容模式'], 0, '测试通过 (SQLite兼容)');
            }
            new PDO("mysql:host={$host};port={$port};charset=utf8mb4", $user, $pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_TIMEOUT => 3
            ]);
            Response::json(['connected' => true], 0, 'MySQL 数据库连接成功');
        } catch (\Throwable $e) {
            Response::error('数据库网络连接失败: ' . $e->getMessage(), 500);
        }
    }

    public function database(Request $request): void
    {
        $this->guardToken($request);
        try {
            $res = $this->installService->setupDatabase($request->input());
            Response::json($res, 0, '数据架构构建成功');
        } catch (\Throwable $e) {
            Response::error('数据库初始化失败: ' . $e->getMessage(), 500);
        }
    }

    public function admin(Request $request): void
    {
        $this->guardToken($request);
        $body = $request->input();
        if (empty($body['username']) || empty($body['password']) || empty($body['email'])) {
            Response::error('管理员参数不完整', 422);
        }
        if ($body['password'] !== ($body['password_confirmation'] ?? '')) {
            Response::error('两次输入的管理员密码不一致', 422);
        }

        try {
            $this->installService->createAdminAccount($body);
            Response::json(null, 0, '管理员配置成功');
        } catch (\Throwable $e) {
            Response::error($e->getMessage(), 422);
        }
    }

    public function notify(Request $request): void
    {
        $this->guardToken($request);
        $channels = $request->input('channels', []);
        try {
            $this->installService->configureNotifications($channels);
            Response::json(null, 0, '初始告警渠道已保存');
        } catch (\Throwable $e) {
            Response::error('保存失败: ' . $e->getMessage(), 500);
        }
    }

    public function complete(Request $request): void
    {
        $token = $request->header('x-install-token');
        $this->guardToken($request);

        try {
            $this->installService->finalizeInstallation($token, $request->ip());
            Response::json(['success' => true], 0, '系统初始化完成，已写入锁文件');
        } catch (\Throwable $e) {
            Response::error('锁定系统失败: ' . $e->getMessage(), 500);
        }
    }

    private function guardToken(Request $request): void
    {
        $token = $request->header('x-install-token');
        if (!$this->installService->verifyInstallToken($token, $request->ip())) {
            Response::error('安装 Token 无效或已过期，请刷新页面重新开始向导', 403, 403);
        }
    }
}
