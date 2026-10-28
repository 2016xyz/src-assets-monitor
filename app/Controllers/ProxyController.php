<?php

namespace App\Controllers;

use App\Core\Crypto;
use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use App\Middleware\SanitizeInputMiddleware;
use App\Services\Proxy\CircuitBreaker;
use App\Services\Proxy\ProxyHealthChecker;

class ProxyController
{
    private ProxyHealthChecker $checker;

    public function __construct()
    {
        $this->checker = new ProxyHealthChecker(new CircuitBreaker());
    }

    public function index(Request $request): void
    {
        $page = max(1, (int)$request->query('page', 1));
        $pageSize = max(1, min(100, (int)$request->query('page_size', 20)));
        $offset = ($page - 1) * $pageSize;

        $proto = $request->query('protocol');
        $health = $request->query('health_status');

        $where = ["1=1"];
        $params = [];
        if ($proto) {
            $where[] = "protocol = ?";
            $params[] = $proto;
        }
        if ($health) {
            $where[] = "health_status = ?";
            $params[] = $health;
        }

        $whereSql = implode(' AND ', $where);
        $total = Database::count('proxies', $whereSql, $params);
        $list = Database::fetchAll("SELECT * FROM proxies WHERE {$whereSql} ORDER BY id DESC LIMIT {$pageSize} OFFSET {$offset}", $params);

        // 密码强制脱敏掩码
        foreach ($list as &$item) {
            $hasPass = !empty($item['auth_pass_encrypted']);
            unset($item['auth_pass_encrypted']);
            $item['auth_pass_masked'] = $hasPass ? '••••••••' : null;
        }

        Response::json([
            'list'      => $list,
            'total'     => $total,
            'page'      => $page,
            'page_size' => $pageSize
        ]);
    }

    public function store(Request $request): void
    {
        $b = $request->input();
        if (empty($b['name']) || empty($b['host']) || empty($b['port'])) {
            Response::error('请补全代理名称、主机与端口', 422);
        }

        $host = trim($b['host']);
        // 严格安全校验：防 CRLF 与特殊字符注入代理隧道
        if (!preg_match('/^[a-zA-Z0-9.\-_]+$/', $host)) {
            Response::error('代理服务器主机地址格式不合法，严禁包含特殊符号或空格换行', 422);
        }

        $port = (int)$b['port'];
        if ($port < 1 || $port > 65535) {
            Response::error('端口号超出合法范围 (1-65535)', 422);
        }

        $proto = strtolower($b['protocol'] ?? 'http');
        if (!in_array($proto, ['http', 'https', 'socks5', 'socks5h'], true)) {
            Response::error('协议类型不支持', 422);
        }

        $safeName = SanitizeInputMiddleware::escapeHtml(trim($b['name']));
        $encPass = !empty($b['auth_pass']) ? Crypto::encrypt($b['auth_pass']) : null;

        $id = Database::insert('proxies', [
            'name'                  => $safeName,
            'protocol'              => $proto,
            'host'                  => $host,
            'port'                  => $port,
            'auth_user'             => !empty($b['auth_user']) ? trim($b['auth_user']) : null,
            'auth_pass_encrypted'   => $encPass,
            'priority'              => (int)($b['priority'] ?? 10),
            'max_concurrency'       => (int)($b['max_concurrency'] ?? 5),
            'rate_limit_per_minute' => (int)($b['rate_limit_per_minute'] ?? 120),
            'status'                => isset($b['status']) ? (int)$b['status'] : 1,
            'health_status'         => 'healthy',
            'created_at'            => date('Y-m-d H:i:s')
        ]);

        Response::json(['id' => $id], 0, '代理节点录入成功');
    }

    public function update(Request $request, $id): void
    {
        $id = (int)$id;
        $proxy = Database::fetchOne("SELECT * FROM proxies WHERE id = ?", [$id]);
        if (!$proxy) Response::error('节点不存在', 404);

        $b = $request->input();
        $data = [];
        if (isset($b['name'])) {
            $data['name'] = SanitizeInputMiddleware::escapeHtml(trim($b['name']));
        }
        if (isset($b['protocol'])) {
            $proto = strtolower($b['protocol']);
            if (in_array($proto, ['http', 'https', 'socks5', 'socks5h'], true)) {
                $data['protocol'] = $proto;
            }
        }
        if (isset($b['host'])) {
            $host = trim($b['host']);
            if (!preg_match('/^[a-zA-Z0-9.\-_]+$/', $host)) {
                Response::error('主机地址格式非法', 422);
            }
            $data['host'] = $host;
        }
        if (isset($b['port'])) {
            $data['port'] = max(1, min(65535, (int)$b['port']));
        }
        if (isset($b['auth_user'])) {
            $data['auth_user'] = trim($b['auth_user']);
        }
        if (!empty($b['auth_pass'])) {
            $data['auth_pass_encrypted'] = Crypto::encrypt($b['auth_pass']);
        }
        if (isset($b['status'])) $data['status'] = (int)$b['status'];
        if (isset($b['priority'])) $data['priority'] = (int)$b['priority'];

        Database::update('proxies', $data, 'id = ?', [$id]);
        Response::json(null, 0, '更新成功');
    }

    public function destroy(Request $request, $id): void
    {
        $id = (int)$id;
        Database::delete('proxies', 'id = ?', [$id]);
        Database::delete('proxy_group_items', 'proxy_id = ?', [$id]);
        Response::json(null, 0, '已删除');
    }

    public function batchImport(Request $request): void
    {
        $content = $request->input('content', '');
        $lines = explode("\n", str_replace("\r", "", $content));
        $count = 0;

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || str_starts_with($line, '#')) continue;

            $parts = explode(':', $line);
            if (count($parts) >= 2) {
                $host = trim($parts[0]);
                $port = (int)$parts[1];

                // 校验格式
                if (!preg_match('/^[a-zA-Z0-9.\-_]+$/', $host) || $port < 1 || $port > 65535) {
                    continue; // 跳过畸形行
                }

                $user = !empty($parts[2]) ? trim($parts[2]) : null;
                $pass = !empty($parts[3]) ? trim($parts[3]) : null;

                Database::insert('proxies', [
                    'name'                => "Node-{$host}:{$port}",
                    'protocol'            => 'http',
                    'host'                => $host,
                    'port'                => $port,
                    'auth_user'           => $user,
                    'auth_pass_encrypted' => $pass ? Crypto::encrypt($pass) : null,
                    'priority'            => 10,
                    'status'              => 1,
                    'health_status'       => 'healthy',
                    'created_at'          => date('Y-m-d H:i:s')
                ]);
                $count++;
            }
        }

        Response::json(['imported' => $count], 0, "成功批量录入 {$count} 个代理");
    }

    public function testSingle(Request $request, $id): void
    {
        $id = (int)$id;
        $proxy = Database::fetchOne("SELECT * FROM proxies WHERE id = ?", [$id]);
        if (!$proxy) Response::error('代理不存在', 404);

        $res = $this->checker->check($proxy);
        if ($res['healthy']) {
            Response::json($res, 0, '出站正常');
        } else {
            Response::error($res['error'] ?? '探针失败', 500, 500, $res);
        }
    }

    public function stats(Request $request): void
    {
        $total = Database::count('proxies');
        $healthy = Database::count('proxies', "health_status = 'healthy' AND status = 1");
        $semi = Database::count('proxies', "health_status = 'semi-open'");
        $unhealthy = Database::count('proxies', "health_status = 'unhealthy'");

        $avgRow = Database::fetchOne("SELECT AVG(latency_ms) as avg_lat FROM proxies WHERE latency_ms > 0");
        $avgLat = (int)($avgRow['avg_lat'] ?? 0);

        Response::json([
            'total'       => $total,
            'healthy'     => $healthy,
            'semi_open'   => $semi,
            'unhealthy'   => $unhealthy,
            'avg_latency' => $avgLat
        ]);
    }
}
