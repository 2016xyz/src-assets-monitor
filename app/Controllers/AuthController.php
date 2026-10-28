<?php

namespace App\Controllers;

use App\Core\Cache;
use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use App\Middleware\AuthMiddleware;
use App\Middleware\SanitizeInputMiddleware;

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

        // 账号冻结检查
        if (isset($user['status']) && (int)$user['status'] === 0) {
            Response::error('该账户已被系统管理员冻结停用，请联系管理人员解除', 403, 403);
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
        $sessionUser = AuthMiddleware::user();
        if (!$sessionUser) {
            Response::error('未登录', 401);
        }
        $dbUser = Database::fetchOne("SELECT id, username, email, role, status, created_at FROM users WHERE id = ?", [$sessionUser['id']]);
        Response::json($dbUser ?: $sessionUser);
    }

    /**
     * PUT /api/v1/auth/profile - 当前用户修改用户名与强制绑定/修改邮箱
     */
    public function updateProfile(Request $request): void
    {
        $curUser = AuthMiddleware::user();
        $userId = $curUser['id'];

        $body = $request->input();
        $username = trim($body['username'] ?? '');
        $email = trim($body['email'] ?? '');

        if (!$username || strlen($username) < 3 || strlen($username) > 30) {
            Response::error('用户名长度必须在 3-30 个字符之间', 422);
        }
        if (!preg_match('/^[a-zA-Z0-9_\-\x{4e00}-\x{9fa5}]+$/u', $username)) {
            Response::error('用户名格式非法，仅允许汉字、英文字母、数字及连字符', 422);
        }

        // 强制绑定邮箱并执行合法性校验
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            Response::error('系统强制要求绑定有效电子邮箱，请填写合法邮箱地址', 422);
        }

        // 唯一性排重检测 (排除自己)
        $dupUser = Database::fetchOne("SELECT id FROM users WHERE username = ? AND id != ?", [$username, $userId]);
        if ($dupUser) {
            Response::error('该用户名已被其他成员占用', 422);
        }
        $dupEmail = Database::fetchOne("SELECT id FROM users WHERE email = ? AND id != ?", [$email, $userId]);
        if ($dupEmail) {
            Response::error('该电子邮箱已被绑定至其他账户', 422);
        }

        $safeUsername = SanitizeInputMiddleware::escapeHtml($username);
        $safeEmail = strtolower($email);

        Database::update('users', [
            'username'   => $safeUsername,
            'email'      => $safeEmail,
            'updated_at' => date('Y-m-d H:i:s')
        ], 'id = ?', [$userId]);

        // 更新 Session 缓存中的用户信息
        $auth = $request->header('authorization');
        if ($auth && str_starts_with($auth, 'Bearer ')) {
            $tokenKey = 'token_' . substr($auth, 7);
            $cached = Cache::get($tokenKey, []);
            if (is_array($cached)) {
                $cached['username'] = $safeUsername;
                $cached['email'] = $safeEmail;
                Cache::set($tokenKey, $cached, 86400);
            }
        }

        Response::json([
            'id'       => $userId,
            'username' => $safeUsername,
            'email'    => $safeEmail
        ], 0, '个人资料已更新');
    }

    /**
     * PUT /api/v1/auth/password - 当前用户修改登录密码 (需验证旧密码)
     */
    public function updatePassword(Request $request): void
    {
        $curUser = AuthMiddleware::user();
        $userId = $curUser['id'];

        $body = $request->input();
        $oldPass = $body['old_password'] ?? '';
        $newPass = $body['new_password'] ?? '';
        $confirmPass = $body['new_password_confirmation'] ?? '';

        if (!$oldPass || !$newPass) {
            Response::error('请输入当前旧密码与新密码', 422);
        }

        if ($newPass !== $confirmPass) {
            Response::error('两次输入的新密码不一致', 422);
        }

        // 新密码强度校验：≥8位，必须含大小写字母和数字
        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,64}$/', $newPass)) {
            Response::error('新密码必须不少于8位，且同时包含大写字母、小写字母和数字', 422);
        }

        $user = Database::fetchOne("SELECT password FROM users WHERE id = ?", [$userId]);
        if (!$user || !password_verify($oldPass, $user['password'])) {
            Response::error('当前旧密码验证错误', 422);
        }

        Database::update('users', [
            'password'   => password_hash($newPass, PASSWORD_BCRYPT),
            'updated_at' => date('Y-m-d H:i:s')
        ], 'id = ?', [$userId]);

        Response::json(null, 0, '登录密码修改成功，请妥善保管新凭据');
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
