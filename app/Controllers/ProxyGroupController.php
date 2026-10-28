<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;

class ProxyGroupController
{
    public function index(Request $request): void
    {
        $groups = Database::fetchAll("
            SELECT pg.*, COUNT(pgi.proxy_id) as proxies_count
            FROM proxy_groups pg
            LEFT JOIN proxy_group_items pgi ON pgi.group_id = pg.id
            GROUP BY pg.id
            ORDER BY pg.id DESC
        ");
        Response::json($groups);
    }

    public function store(Request $request): void
    {
        $b = $request->input();
        if (empty($b['name'])) Response::error('代理组名称不可为空', 422);

        $id = Database::insert('proxy_groups', [
            'name'              => $b['name'],
            'description'       => $b['description'] ?? '',
            'strategy'          => $b['strategy'] ?? 'round-robin',
            'fail_strategy'     => $b['fail_strategy'] ?? 'failover',
            'max_concurrency'   => (int)($b['max_concurrency'] ?? 10),
            'rate_limit_minute' => (int)($b['rate_limit_minute'] ?? 600),
            'created_at'        => date('Y-m-d H:i:s')
        ]);

        if (!empty($b['proxy_ids']) && is_array($b['proxy_ids'])) {
            foreach ($b['proxy_ids'] as $pid) {
                Database::insert('proxy_group_items', [
                    'group_id' => $id,
                    'proxy_id' => (int)$pid
                ]);
            }
        }

        Response::json(['id' => $id], 0, '代理分组创建成功');
    }

    public function destroy(Request $request, $id): void
    {
        $id = (int)$id;
        Database::delete('proxy_groups', 'id = ?', [$id]);
        Database::delete('proxy_group_items', 'group_id = ?', [$id]);
        Response::json(null, 0, '代理组已删除');
    }
}
