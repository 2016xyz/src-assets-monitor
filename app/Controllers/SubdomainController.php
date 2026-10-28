<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use App\Services\Scanner\AssetNameResolver;

class SubdomainController
{
    private AssetNameResolver $nameResolver;

    public function __construct()
    {
        $this->nameResolver = new AssetNameResolver();
    }

    /**
     * GET /api/v1/subdomains - 检索存活子域名资产 (支持按资产名称和来源筛选)
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
        $nameSource = $request->query('asset_name_source');

        $where = ["1=1"];
        $params = [];

        if ($domainId > 0) {
            $where[] = "domain_id = ?";
            $params[] = $domainId;
        }
        if ($kw) {
            // 支持子域名、解析值、资产名称、别名模糊匹配
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
        if ($nameSource) {
            $where[] = "asset_name_source = ?";
            $params[] = $nameSource;
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
            // 设置了别名 -> asset_name 同步为别名，来源标记为 alias
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
            // 清空别名 -> 重新执行优先级链解析
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
