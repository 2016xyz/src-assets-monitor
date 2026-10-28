<?php

namespace App\Middleware;

use App\Core\App;
use App\Core\Database;
use App\Core\Request;
use App\Core\Response;

class EnsureSystemInstalled
{
    public static function check(): bool
    {
        $lockFile = App::runtimePath('install.lock');
        if (!file_exists($lockFile)) {
            return false;
        }

        try {
            $row = Database::fetchOne("SELECT `value` FROM `settings` WHERE `key` = 'installed'");
            return !empty($row) && (string)$row['value'] === '1';
        } catch (\Throwable $e) {
            return false;
        }
    }

    public static function handle(Request $request): void
    {
        $uri = $request->uri();
        $isInstalled = self::check();
        $isInstallRoute = str_starts_with($uri, '/api/v1/install') || str_starts_with($uri, '/install');

        // 情况一：已安装，试图请求除 status 以外的安装写接口
        if ($isInstalled && $isInstallRoute && $uri !== '/api/v1/install/status') {
            Response::error('系统已初始化完成，安装入口已被锁定。', 403, 403);
        }

        // 情况二：未安装，试图请求业务接口
        if (!$isInstalled && !$isInstallRoute && $uri !== '/' && !str_starts_with($uri, '/assets')) {
            Response::json([
                'install_required' => true,
                'redirect'         => '/install'
            ], 428, '系统尚未安装，请前往安装向导完成初始化', 428);
        }
    }
}
