<?php

namespace App\Middleware;

use App\Core\Cache;
use App\Core\Request;
use App\Core\Response;

class AuthMiddleware
{
    private static ?array $currentUser = null;

    public static function handle(Request $request): void
    {
        $auth = $request->header('authorization');
        if (!$auth || !str_starts_with($auth, 'Bearer ')) {
            Response::error('身份凭据缺失，请先登录', 401, 401);
        }

        $token = substr($auth, 7);
        $user = Cache::get('token_' . $token);

        if (!$user) {
            Response::error('登录已过期或凭据失效，请重新登录', 401, 401);
        }

        self::$currentUser = $user;
    }

    public static function user(): ?array
    {
        return self::$currentUser;
    }

    public static function id(): int
    {
        return self::$currentUser['id'] ?? 1;
    }
}
