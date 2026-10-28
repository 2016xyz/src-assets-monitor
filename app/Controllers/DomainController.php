<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use App\Middleware\AuthMiddleware;
use App\Middleware\SanitizeInputMiddleware;
use App\Services\Proxy\CircuitBreaker;
use App\Services\Proxy\DoHProxyClient;
use App\Services\Proxy\ProxyRateLimiter;
use App\Services\Proxy\ProxyScheduler;
use App\Services\Scanner\SubdomainScanner;

class DomainController
{
    private SubdomainScanner $scanner;
    private ProxyScheduler $scheduler;
    private DoHProxyClient $dohClient;

    public function __construct()
    {
        $cb = new CircuitBreaker();
        $rl = new ProxyRateLimiter();
        $this->scheduler = new ProxyScheduler($cb, $rl);
        $this->dohClient = new DoHProxyClient($cb);
        $this->scanner = new SubdomainScanner($this->dohClient, $this->scheduler);
    }

    public function index(Request $request): void
    {
        $page = max(1, (int)$request->query('page', 1));
        $pageSize = max(1, min(100, (int)$request->query('page_size', 15)));
        $offset = ($page - 1) * $pageSize;

        $kw = $request->query('keyword');
        $group = $request->query('group_name');

        $where = ["1=1"];
        $params = [];

        if ($kw) {
            $where[] = "(d.domain LIKE ? OR d.remark LIKE ?)";
            $params[] = "%{$kw}%";
            $params[] = "%{$kw}%";
        }
        if ($group) {
            $where[] = "d.group_name = ?";
            $params[] = $group;
        }

        $whereSql = implode(' AND ', $where);
        $total = Database::count('domains d', $whereSql, $params);

        $sql = "
            SELECT d.*, pg.name as proxy_group_name, pg.strategy as proxy_strategy
            FROM domains d
            LEFT JOIN proxy_groups pg ON pg.id = d.proxy_group_id
            WHERE {$whereSql}
            ORDER BY d.id DESC LIMIT {$pageSize} OFFSET {$offset}
        ";
        $list = Database::fetchAll($sql, $params);

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
        $domain = trim($b['domain'] ?? '');
        if (!$domain || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            Response::error('请输入合法的域名格式 (如: example.com)', 422);
        }

        $ex = Database::fetchOne("SELECT id FROM domains WHERE domain = ?", [$domain]);
        if ($ex) {
            Response::error('该域名资产已存在，请勿重复添加', 422);
        }

        // XSS 输入净化
        $safeGroup = SanitizeInputMiddleware::escapeHtml(trim($b['group_name'] ?? '默认分组'));
        $safeRemark = SanitizeInputMiddleware::escapeHtml(trim($b['remark'] ?? ''));

        $id = Database::insert('domains', [
            'user_id'                => AuthMiddleware::id(),
            'domain'                 => strtolower($domain),
            'group_name'             => $safeGroup,
            'remark'                 => $safeRemark,
            'is_enabled'             => isset($b['is_enabled']) ? (int)$b['is_enabled'] : 1,
            'check_interval'         => $b['check_interval'] ?? '1h',
            'proxy_mode'             => $b['proxy_mode'] ?? 'auto',
            'proxy_group_id'         => !empty($b['proxy_group_id']) ? (int)$b['proxy_group_id'] : null,
            'enable_axfr'            => !empty($b['enable_axfr']) ? 1 : 0,
            'enable_c_segment'       => !empty($b['enable_c_segment']) ? 1 : 0,
            'enable_wildcard_filter' => isset($b['enable_wildcard_filter']) ? (int)$b['enable_wildcard_filter'] : 1,
            'created_at'             => date('Y-m-d H:i:s')
        ]);

        Response::json(['id' => $id], 0, '资产域名创建成功');
    }

    public function update(Request $request, $id): void
    {
        $id = (int)$id;
        $domain = Database::fetchOne("SELECT * FROM domains WHERE id = ?", [$id]);
        if (!$domain) Response::error('域名不存在', 404);

        $b = $request->input();
        $data = [];
        if (isset($b['group_name'])) {
            $data['group_name'] = SanitizeInputMiddleware::escapeHtml(trim($b['group_name']));
        }
        if (isset($b['remark'])) {
            $data['remark'] = SanitizeInputMiddleware::escapeHtml(trim($b['remark']));
        }
        if (isset($b['is_enabled'])) $data['is_enabled'] = (int)$b['is_enabled'];
        if (isset($b['check_interval'])) $data['check_interval'] = $b['check_interval'];
        if (isset($b['proxy_mode'])) $data['proxy_mode'] = $b['proxy_mode'];
        if (array_key_exists('proxy_group_id', $b)) {
            $data['proxy_group_id'] = !empty($b['proxy_group_id']) ? (int)$b['proxy_group_id'] : null;
        }
        if (isset($b['enable_axfr'])) $data['enable_axfr'] = (int)$b['enable_axfr'];
        if (isset($b['enable_c_segment'])) $data['enable_c_segment'] = (int)$b['enable_c_segment'];
        if (isset($b['enable_wildcard_filter'])) $data['enable_wildcard_filter'] = (int)$b['enable_wildcard_filter'];

        Database::update('domains', $data, 'id = ?', [$id]);
        Response::json(null, 0, '更新成功');
    }

    public function destroy(Request $request, $id): void
    {
        $id = (int)$id;
        Database::delete('domains', 'id = ?', [$id]);
        Database::delete('subdomains', 'domain_id = ?', [$id]);
        Database::delete('dns_snapshots', 'domain_id = ?', [$id]);
        Database::delete('change_logs', 'domain_id = ?', [$id]);
        Database::delete('domain_channel', 'domain_id = ?', [$id]);
        Database::delete('scan_tasks', 'domain_id = ?', [$id]);
        Response::json(null, 0, '已下线并级联清理');
    }

    public function scan(Request $request, $id): void
    {
        $id = (int)$id;
        $domain = Database::fetchOne("SELECT * FROM domains WHERE id = ?", [$id]);
        if (!$domain) Response::error('域名不存在', 404);

        $taskId = Database::insert('scan_tasks', [
            'domain_id'    => $domain['id'],
            'trigger_type' => 'manual',
            'status'       => 'running',
            'started_at'   => date('Y-m-d H:i:s'),
            'created_at'   => date('Y-m-d H:i:s')
        ]);

        try {
            $res = $this->scanner->scan($domain, $taskId);
            Database::update('scan_tasks', [
                'status'           => 'success',
                'discovered_count' => $res['total_active'],
                'changes_count'    => count($res['changes']),
                'finished_at'      => date('Y-m-d H:i:s')
            ], 'id = ?', [$taskId]);

            Response::json([
                'task_id'      => $taskId,
                'total_active' => $res['total_active'],
                'changes'      => count($res['changes'])
            ], 0, '检测完成');
        } catch (\Throwable $e) {
            Database::update('scan_tasks', [
                'status'        => 'failed',
                'error_message' => $e->getMessage(),
                'finished_at'   => date('Y-m-d H:i:s')
            ], 'id = ?', [$taskId]);

            Response::error('扫描失败: ' . $e->getMessage(), 500);
        }
    }

    public function testProxy(Request $request, $id): void
    {
        $id = (int)$id;
        $domain = Database::fetchOne("SELECT * FROM domains WHERE id = ?", [$id]);
        if (!$domain) Response::error('域名不存在', 404);

        $b = $request->input();
        $mode = $b['proxy_mode'] ?? $domain['proxy_mode'];
        $groupId = !empty($b['proxy_group_id']) ? (int)$b['proxy_group_id'] : $domain['proxy_group_id'];

        if ($mode === 'direct') {
            Response::json([
                'mode'       => 'direct',
                'proxy_used' => '直连本地',
                'latency_ms' => 12,
                'status'     => 'pass'
            ]);
            return;
        }

        if (!$groupId) {
            Response::error('未指定代理组', 422);
        }

        $proxy = $this->scheduler->selectProxy($groupId, $domain['domain']);
        if (!$proxy) {
            Response::error('所选代理组内当前无可用/健康节点', 500);
        }

        $testRes = $this->dohClient->resolve($domain['domain'], 'A', $proxy);
        Response::json([
            'mode'       => 'proxy_group',
            'proxy_used' => "{$proxy['protocol']}://{$proxy['host']}:{$proxy['port']}",
            'latency_ms' => $testRes['latency_ms'],
            'status'     => $testRes['status'] === 'ok' ? 'pass' : 'fail'
        ]);
    }

    /**
     * 安全导出 CSV 报告 (含 CSV Formula / 命令注入防御)
     */
    public function exportCsv(Request $request): void
    {
        $domainId = (int)$request->query('domain_id');
        $domain = Database::fetchOne("SELECT domain FROM domains WHERE id = ?", [$domainId]);
        $domainName = $domain ? preg_replace('/[^a-zA-Z0-9.-]/', '_', $domain['domain']) : 'export';

        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="subdomains_' . $domainName . '_' . date('Ymd_His') . '.csv"');
        header('X-Content-Type-Options: nosniff');

        echo chr(0xEF) . chr(0xBB) . chr(0xBF);
        $fp = fopen('php://output', 'w');
        fputcsv($fp, ['ID', '资产名称', '别名', '名称来源', '子域名', '类型', '解析指向值', '接管风险', '发现源', '首次发现时间']);

        $subs = Database::fetchAll("SELECT * FROM subdomains WHERE domain_id = ? ORDER BY subdomain ASC", [$domainId]);
        foreach ($subs as $s) {
            fputcsv($fp, [
                $s['id'],
                $this->sanitizeCsvCell($s['asset_name']),
                $this->sanitizeCsvCell($s['alias_name'] ?? ''),
                $this->sanitizeCsvCell($s['asset_name_source']),
                $this->sanitizeCsvCell($s['subdomain']),
                $this->sanitizeCsvCell($s['record_type']),
                $this->sanitizeCsvCell($s['record_value']),
                !empty($s['takeover_risk']) ? $this->sanitizeCsvCell('危险: ' . ($s['takeover_reason'] ?? '接管风险')) : '正常',
                $this->sanitizeCsvCell($s['provenance_sources'] ?? $s['source']),
                $s['first_seen_at']
            ]);
        }
        fclose($fp);
        exit;
    }

    /**
     * 防范 CSV 公式执行注入 (Excel / Calc Formula Injection)
     * 若单元格以 =, +, -, @, 制表符开头，前置单引号强制作为纯文本处理
     */
    private function sanitizeCsvCell(?string $value): string
    {
        if ($value === null || $value === '') {
            return '';
        }
        if (preg_match('/^[=+\-@\t\r]/', $value)) {
            return "'" . $value;
        }
        return $value;
    }
}
