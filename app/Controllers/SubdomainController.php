<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use App\Services\Scanner\AssetDeepProbe;
use App\Services\Scanner\AssetNameResolver;

class SubdomainController
{
    private AssetNameResolver $nameResolver;
    private AssetDeepProbe $deepProbe;

    public function __construct()
    {
        $this->nameResolver = new AssetNameResolver();
        $this->deepProbe = new AssetDeepProbe();
    }

    /**
     * GET /api/v1/subdomains - 检索特定主域名下的存活子域名资产
     */
    public function index(Request $request): void
    {
        $domainId = (int)$request->query('domain_id');
        $page = max(1, (int)$request->query('page', 1));
        $pageSize = max(1, min(200, (int)$request->query('page_size', 50)));
        $offset = ($page - 1) * $pageSize;

        $kw = $request->query('keyword');
        $status = $request->query('status');
        $type = $request->query('record_type');
        $takeoverOnly = (bool)$request->query('takeover_only', false);

        $where = ["1=1"];
        $params = [];

        if ($domainId > 0) {
            $where[] = "domain_id = ?";
            $params[] = $domainId;
        }
        if ($kw) {
            $where[] = "(subdomain LIKE ? OR record_value LIKE ? OR asset_name LIKE ? OR alias_name LIKE ?)";
            $params[] = "%{$kw}%";
            $params[] = "%{$kw}%";
            $params[] = "%{$kw}%";
            $params[] = "%{$kw}%";
        }
        if ($status) {
            $where[] = "status = ?";
            $params[] = $status;
        }
        if ($type) {
            $where[] = "record_type = ?";
            $params[] = $type;
        }
        if ($takeoverOnly) {
            $where[] = "takeover_risk = 1";
        }

        $whereSql = implode(' AND ', $where);
        $total = Database::count('subdomains', $whereSql, $params);
        $list = Database::fetchAll("SELECT * FROM subdomains WHERE {$whereSql} ORDER BY id DESC LIMIT {$pageSize} OFFSET {$offset}", $params);

        Response::json([
            'list'      => $list,
            'total'     => $total,
            'page'      => $page,
            'page_size' => $pageSize
        ]);
    }

    /**
     * GET /api/v1/subdomains/all - 全局跨主域名资产总库 (支持接管风险一键筛选与全量组合检索)
     */
    public function getAll(Request $request): void
    {
        $page = max(1, (int)$request->query('page', 1));
        $pageSize = max(1, min(100, (int)$request->query('page_size', 20)));
        $offset = ($page - 1) * $pageSize;

        $domainId = (int)$request->query('domain_id');
        $kw = $request->query('keyword');
        $takeoverOnly = (bool)$request->query('takeover_only', false);
        $recordType = $request->query('record_type');
        $source = $request->query('source');

        $where = ["1=1"];
        $params = [];

        if ($domainId > 0) {
            $where[] = "s.domain_id = ?";
            $params[] = $domainId;
        }
        if ($kw) {
            $where[] = "(s.subdomain LIKE ? OR s.asset_name LIKE ? OR s.record_value LIKE ? OR d.domain LIKE ?)";
            $params[] = "%{$kw}%";
            $params[] = "%{$kw}%";
            $params[] = "%{$kw}%";
            $params[] = "%{$kw}%";
        }
        if ($takeoverOnly) {
            $where[] = "s.takeover_risk = 1";
        }
        if ($recordType) {
            $where[] = "s.record_type = ?";
            $params[] = $recordType;
        }
        if ($source) {
            $where[] = "s.source = ?";
            $params[] = $source;
        }

        $whereSql = implode(' AND ', $where);
        $total = Database::count('subdomains s LEFT JOIN domains d ON d.id = s.domain_id', $whereSql, $params);

        $sql = "
            SELECT s.*, d.domain as main_domain, d.group_name
            FROM subdomains s
            LEFT JOIN domains d ON d.id = s.domain_id
            WHERE {$whereSql}
            ORDER BY s.takeover_risk DESC, s.id DESC LIMIT {$pageSize} OFFSET {$offset}
        ";
        $list = Database::fetchAll($sql, $params);

        // 统计概览指标
        $takeoverCount = Database::count('subdomains', 'takeover_risk = 1');
        $activeTotal = Database::count('subdomains', "status = 'active'");

        Response::json([
            'list'           => $list,
            'total'          => $total,
            'takeover_count' => $takeoverCount,
            'active_total'   => $activeTotal,
            'page'           => $page,
            'page_size'      => $pageSize
        ]);
    }

    /**
     * GET /api/v1/subdomains/{id}/portrait - 获取单条子域名实时深度全景画像 (含SSL/Web指纹/IP归属/DNS)
     */
    public function getPortrait(Request $request, $id): void
    {
        $id = (int)$id;
        $sub = Database::fetchOne("SELECT * FROM subdomains WHERE id = ?", [$id]);
        if (!$sub) {
            Response::error('资产不存在', 404);
        }

        $domain = Database::fetchOne("SELECT * FROM domains WHERE id = ?", [$sub['domain_id']]);
        $portrait = $this->deepProbe->inspect($sub['subdomain']);
        $portrait['asset_record'] = $sub;
        $portrait['main_domain'] = $domain ? $domain['domain'] : '';

        Response::json($portrait);
    }

    /**
     * GET /api/v1/subdomains/export-all - 导出全局所有子域名资产为 CSV 格式
     */
    public function exportAllCsv(Request $request): void
    {
        $sql = "
            SELECT s.subdomain, s.asset_name, s.record_type, s.record_value, s.source, s.status, s.takeover_risk, d.domain as main_domain, s.first_seen_at
            FROM subdomains s
            LEFT JOIN domains d ON d.id = s.domain_id
            ORDER BY s.domain_id ASC, s.id DESC
        ";
        $list = Database::fetchAll($sql);

        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="src_all_subdomains_' . date('Ymd_His') . '.csv"');

        $out = fopen('php://output', 'w');
        // 输出 UTF-8 BOM 防 Excel 乱码
        fputs($out, "\xEF\xBB\xBF");
        fputcsv($out, ['子域名', '资产名称', '解析类型', '解析指向值', '归属主域名', '发现来源', '存活状态', '接管风险', '首次发现时间']);

        foreach ($list as $r) {
            fputcsv($out, [
                $r['subdomain'],
                $r['asset_name'] ?: $r['subdomain'],
                $r['record_type'],
                $r['record_value'],
                $r['main_domain'] ?? '',
                $r['source'],
                $r['status'],
                $r['takeover_risk'] ? '⚠️ 是' : '否',
                $r['first_seen_at']
            ]);
        }
        fclose($out);
        exit;
    }

    /**
     * PUT /api/v1/subdomains/{id}/alias - 编辑资产别名 (最高优先级)
     */
    public function updateAlias(Request $request, $id): void
    {
        $id = (int)$id;
        $sub = Database::fetchOne("SELECT * FROM subdomains WHERE id = ?", [$id]);
        if (!$sub) {
            Response::error('目标子域名资产不存在', 404);
        }

        $body = $request->input();
        $alias = isset($body['alias_name']) ? trim($body['alias_name']) : null;
        $now = date('Y-m-d H:i:s');

        if ($alias !== null && $alias !== '') {
            $safeAlias = htmlspecialchars($alias, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            Database::update('subdomains', [
                'alias_name'            => $safeAlias,
                'asset_name'            => $safeAlias,
                'asset_name_source'     => 'alias',
                'asset_name_updated_at' => $now,
                'updated_at'            => $now
            ], 'id = ?', [$id]);

            Response::json([
                'id'                => $id,
                'asset_name'        => $safeAlias,
                'alias_name'        => $safeAlias,
                'asset_name_source' => 'alias'
            ], 0, '自定义别名已生效');
        } else {
            $domain = Database::fetchOne("SELECT domain, proxy_mode, proxy_group_id FROM domains WHERE id = ?", [$sub['domain_id']]);
            $mainDomain = $domain ? $domain['domain'] : $sub['subdomain'];

            $res = $this->nameResolver->resolve(
                $sub['subdomain'],
                $mainDomain,
                $sub['record_type'],
                $sub['record_value'],
                null
            );

            Database::update('subdomains', [
                'alias_name'            => null,
                'asset_name'            => $res['asset_name'],
                'asset_name_source'     => $res['asset_name_source'],
                'asset_name_updated_at' => $res['asset_name_updated_at'],
                'updated_at'            => $now
            ], 'id = ?', [$id]);

            Response::json([
                'id'                => $id,
                'asset_name'        => $res['asset_name'],
                'alias_name'        => null,
                'asset_name_source' => $res['asset_name_source']
            ], 0, '别名已清空，资产名称已自动重识别');
        }
    }

    /**
     * POST /api/v1/subdomains/{id}/resolve-name - 单条子域名手动触发名称识别
     */
    public function resolveSingleName(Request $request, $id): void
    {
        $id = (int)$id;
        $sub = Database::fetchOne("SELECT * FROM subdomains WHERE id = ?", [$id]);
        if (!$sub) {
            Response::error('目标子域名资产不存在', 404);
        }

        $domain = Database::fetchOne("SELECT * FROM domains WHERE id = ?", [$sub['domain_id']]);
        $mainDomain = $domain ? $domain['domain'] : $sub['subdomain'];

        $res = $this->nameResolver->resolve(
            $sub['subdomain'],
            $mainDomain,
            $sub['record_type'],
            $sub['record_value'],
            $sub['alias_name']
        );

        Database::update('subdomains', [
            'asset_name'            => $res['asset_name'],
            'asset_name_source'     => $res['asset_name_source'],
            'asset_name_updated_at' => $res['asset_name_updated_at'],
            'updated_at'            => date('Y-m-d H:i:s')
        ], 'id = ?', [$id]);

        Response::json([
            'id'                    => $id,
            'subdomain'             => $sub['subdomain'],
            'asset_name'            => $res['asset_name'],
            'asset_name_source'     => $res['asset_name_source'],
            'asset_name_updated_at' => $res['asset_name_updated_at']
        ], 0, '资产名称重识别完成');
    }

    /**
     * POST /api/v1/domains/{id}/resolve-names - 批量重识别主域名下所有子域名名称
     */
    public function resolveDomainNames(Request $request, $id): void
    {
        $domainId = (int)$id;
        $domain = Database::fetchOne("SELECT * FROM domains WHERE id = ?", [$domainId]);
        if (!$domain) {
            Response::error('主域名不存在', 404);
        }

        $subs = Database::fetchAll("SELECT * FROM subdomains WHERE domain_id = ? AND status = 'active'", [$domainId]);
        $count = 0;

        foreach ($subs as $sub) {
            $res = $this->nameResolver->resolve(
                $sub['subdomain'],
                $domain['domain'],
                $sub['record_type'],
                $sub['record_value'],
                $sub['alias_name']
            );

            Database::update('subdomains', [
                'asset_name'            => $res['asset_name'],
                'asset_name_source'     => $res['asset_name_source'],
                'asset_name_updated_at' => $res['asset_name_updated_at'],
                'updated_at'            => date('Y-m-d H:i:s')
            ], 'id = ?', [$sub['id']]);

            $count++;
        }

        Response::json(['resolved_count' => $count], 0, "成功重新识别 {$count} 个子域名的资产名称");
    }
}
