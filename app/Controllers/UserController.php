<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use App\Middleware\AuthMiddleware;
use App\Middleware\SanitizeInputMiddleware;

class UserController
{
    /**
     * 权限断言：仅 admin 超级管理角色可操作多用户管理模块
     */
    private function guardAdmin(): void
    {
        $curUser = AuthMiddleware::user();
        if (!$curUser || ($curUser['role'] ?? '') !== 'admin') {
            Response::error('无权操作: 多用户配置仅限系统特权管理员访问', 403, 403);
        }
    }

    /**
     * GET /api/v1/users - 多用户列表分页与检索
     */
    public function index(Request $request): void
    {
        $this->guardAdmin();

        $page = max(1, (int)$request->query('page', 1));
        $pageSize = max(1, min(100, (int)$request->query('page_size', 15)));
        $offset = ($page - 1) * $pageSize;

        $kw = $request->query('keyword');
        $role = $request->query('role');
        $status = $request->query('status');

        $where = ["1=1"];
        $params = [];

        if ($kw) {
            $where[] = "(username LIKE ? OR email LIKE ?)";
            $params[] = "%{$kw}%";
            $params[] = "%{$kw}%";
        }
        if ($role) {
            $where[] = "role = ?";
            $params[] = $role;
        }
        if ($status !== null && $status !== '') {
            $where[] = "status = ?";
            $params[] = (int)$status;
        }

        $whereSql = implode(' AND ', $where);
        $total = Database::count('users', $whereSql, $params);
        $list = Database::fetchAll("SELECT id, username, email, role, status, failed_login_count, created_at, updated_at FROM users WHERE {$whereSql} ORDER BY id DESC LIMIT {$pageSize} OFFSET {$offset}", $params);

        Response::json([
            'list'      => $list,
            'total'     => $total,
            'page'      => $page,
            'page_size' => $pageSize
        ]);
    }

    /**
     * POST /api/v1/users - 管理员创建新成员 (强制绑定合法邮箱)
     */
    public function store(Request $request): void
    {
        $this->guardAdmin();

        $b = $request->input();
        $username = trim($b['username'] ?? '');
        $email = trim($b['email'] ?? '');
        $password = $b['password'] ?? '';
        $role = in_array($b['role'] ?? '', ['admin', 'user'], true) ? $b['role'] : 'user';

        if (!$username || strlen($username) < 3 || strlen($username) > 30) {
            Response::error('用户名必须在 3-30 个字符之间', 422);
        }

        // 强制绑定邮箱并执行 RFC 格式校验
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            Response::error('必须为该成员绑定有效的电子邮箱地址', 422);
        }

        // 密码强度校验：≥8位，含大小写和数字
        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,64}$/', $password)) {
            Response::error('初始密码必须不少于8位，且同时包含大写字母、小写字母和数字', 422);
        }

        // 排重检测
        if (Database::fetchOne("SELECT id FROM users WHERE username = ?", [$username])) {
            Response::error('该登录用户名已被占用', 422);
        }
        if (Database::fetchOne("SELECT id FROM users WHERE email = ?", [$email])) {
            Response::error('该电子邮箱已被绑定至其他成员', 422);
        }

        $safeName = SanitizeInputMiddleware::escapeHtml($username);
        $safeEmail = strtolower($email);

        $id = Database::insert('users', [
            'username'   => $safeName,
            'email'      => $safeEmail,
            'password'   => password_hash($password, PASSWORD_BCRYPT),
            'role'       => $role,
            'status'     => isset($b['status']) ? (int)$b['status'] : 1,
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s')
        ]);

        Response::json(['id' => $id], 0, '新用户成员配置成功');
    }

    /**
     * PUT /api/v1/users/{id} - 管理员修改成员资料与重置密码
     */
    public function update(Request $request, $id): void
    {
        $this->guardAdmin();
        $id = (int)$id;

        $user = Database::fetchOne("SELECT id FROM users WHERE id = ?", [$id]);
        if (!$user) {
            Response::error('目标用户不存在', 404);
        }

        $b = $request->input();
        $data = ['updated_at' => date('Y-m-d H:i:s')];

        if (!empty($b['username'])) {
            $username = trim($b['username']);
            if (Database::fetchOne("SELECT id FROM users WHERE username = ? AND id != ?", [$username, $id])) {
                Response::error('该用户名已被占用', 422);
            }
            $data['username'] = SanitizeInputMiddleware::escapeHtml($username);
        }

        if (array_key_exists('email', $b)) {
            $email = trim($b['email']);
            if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                Response::error('系统强制要求绑定有效电子邮箱，邮箱不可为空', 422);
            }
            if (Database::fetchOne("SELECT id FROM users WHERE email = ? AND id != ?", [$email, $id])) {
                Response::error('该电子邮箱已被其他账户绑定', 422);
            }
            $data['email'] = strtolower($email);
        }

        if (isset($b['role']) && in_array($b['role'], ['admin', 'user'], true)) {
            $data['role'] = $b['role'];
        }

        if (isset($b['status'])) {
            $data['status'] = (int)$b['status'];
        }

        // 管理员重置密码
        if (!empty($b['password'])) {
            $pass = $b['password'];
            if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,64}$/', $pass)) {
                Response::error('重置密码必须不少于8位，且同时包含大小写字母和数字', 422);
            }
            $data['password'] = password_hash($pass, PASSWORD_BCRYPT);
            $data['failed_login_count'] = 0; // 重置失败次数
            $data['locked_until'] = null;
        }

        Database::update('users', $data, 'id = ?', [$id]);
        Response::json(null, 0, '用户资料已更新');
    }

    /**
     * DELETE /api/v1/users/{id} - 管理员移除成员账号 (防误删自身)
     */
    public function destroy(Request $request, $id): void
    {
        $this->guardAdmin();
        $id = (int)$id;

        $curUser = AuthMiddleware::user();
        if ($curUser && (int)$curUser['id'] === $id) {
            Response::error('安全阻断: 严禁在管理面板中删除当前正在登录的自身管理员账号', 422);
        }

        Database::delete('users', 'id = ?', [$id]);
        Response::json(null, 0, '用户已成功注销移除');
    }
}
