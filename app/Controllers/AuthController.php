<?php

namespace App\Controllers;

use App\Core\Cache;
use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use App\Middleware\AuthMiddleware;

class AuthController
{
    public function captcha(Request $request): void
    {
        $num1 = mt_rand(1, 15);
        $num2 = mt_rand(1, 15);
        $ans = $num1 + $num2;
        $key = 'cap_' . bin2hex(random_bytes(16));
        Cache::set($key, (string)$ans, 300);

        $svg = "<svg width=\"120\" height=\"40\" xmlns=\"http://www.w3.org/2000/svg\">" .
               "<rect width=\"120\" height=\"40\" fill=\"#EFF6FF\" rx=\"6\"/>" .
               "<text x=\"20\" y=\"26\" font-family=\"monospace\" font-size=\"20\" font-weight=\"bold\" fill=\"#2563EB\">{$num1} + {$num2} = ?</text>" .
               "</svg>";

        Response::json([
            'key' => $key,
            'svg' => $svg
        ]);
    }

    public function login(Request $request): void
    {
        $body = $request->input();
        $username = trim($body['username'] ?? '');
        $password = $body['password'] ?? '';
        $capKey = $body['captcha_key'] ?? '';
        $capCode = trim($body['captcha_code'] ?? '');

        // 验证码校验
        $realAns = Cache::get($capKey);
        if ($realAns === null || $realAns !== $capCode) {
            Response::error('图形验证码错误或已失效', 422);
        }
        Cache::delete($capKey);

        // 锁定检查
        $failKey = 'login_fail_' . md5($username);
        $fails = (int)Cache::get($failKey, 0);
        if ($fails >= 5) {
            Response::error('连续密码错误超过5次，该账户已被安全锁定15分钟', 429, 429);
        }

        $user = Database::fetchOne("SELECT * FROM users WHERE username = ? OR email = ?", [$username, $username]);
        if (!$user || !password_verify($password, $user['password'])) {
            Cache::set($failKey, $fails + 1, 900);
            Database::insert('login_logs', [
                'user_id'     => $user['id'] ?? null,
                'username'    => $username,
                'client_ip'   => $request->ip(),
                'user_agent'  => substr($request->header('user-agent', ''), 0, 500),
                'status'      => 0,
                'fail_reason' => '密码或账号不匹配',
                'created_at'  => date('Y-m-d H:i:s')
            ]);
            $remain = 5 - ($fails + 1);
            Response::error("账号或密码错误，剩余尝试次数: {$remain}", 401, 401);
        }

        // 登录成功
        Cache::delete($failKey);
        $token = bin2hex(random_bytes(24));
        Cache::set('token_' . $token, [
            'id'       => $user['id'],
            'username' => $user['username'],
            'email'    => $user['email'],
            'role'     => $user['role']
        ], 86400);

        Database::insert('login_logs', [
            'user_id'    => $user['id'],
            'username'   => $user['username'],
            'client_ip'  => $request->ip(),
            'user_agent' => substr($request->header('user-agent', ''), 0, 500),
            'status'     => 1,
            'created_at' => date('Y-m-d H:i:s')
        ]);

        Response::json([
            'token' => $token,
            'user'  => [
                'id'       => $user['id'],
                'username' => $user['username'],
                'email'    => $user['email'],
                'role'     => $user['role']
            ]
        ], 0, '登录成功');
    }

    public function me(Request $request): void
    {
        $user = AuthMiddleware::user();
        Response::json($user);
    }

    public function logout(Request $request): void
    {
        $auth = $request->header('authorization');
        if ($auth && str_starts_with($auth, 'Bearer ')) {
            Cache::delete('token_' . substr($auth, 7));
        }
        Response::json(null, 0, '已成功登出');
    }
}
