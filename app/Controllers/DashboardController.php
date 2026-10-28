<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;

class DashboardController
{
    public function stats(Request $request): void
    {
        $domainCount = Database::count('domains');
        $subdomainCount = Database::count('subdomains', "status = 'active'");
        $today = date('Y-m-d 00:00:00');

        $todayNew = Database::count('change_logs', "change_type = 'added' AND created_at >= ?", [$today]);
        $todayChanged = Database::count('change_logs', "change_type IN ('changed', 'txt_update') AND created_at >= ?", [$today]);

        $totalProxies = Database::count('proxies');
        $healthyProxies = Database::count('proxies', "status = 1 AND health_status = 'healthy'");
        $healthRate = $totalProxies > 0 ? round(($healthyProxies / $totalProxies) * 100, 1) : 100.0;

        Response::json([
            'domains_count'    => $domainCount,
            'subdomains_count' => $subdomainCount,
            'today_new'        => $todayNew,
            'today_changed'    => $todayChanged,
            'proxy_health_rate'=> "{$healthRate}%",
            'proxies_online'   => "{$healthyProxies}/{$totalProxies}"
        ]);
    }

    public function trends(Request $request): void
    {
        $dates = [];
        $values = [];
        for ($i = 13; $i >= 0; $i--) {
            $d = date('m-d', strtotime("-{$i} days"));
            $dates[] = $d;
            $start = date('Y-m-d 00:00:00', strtotime("-{$i} days"));
            $end = date('Y-m-d 23:59:59', strtotime("-{$i} days"));
            $cnt = Database::count('change_logs', "change_type = 'added' AND created_at BETWEEN ? AND ?", [$start, $end]);
            $values[] = $cnt;
        }

        Response::json([
            'dates'  => $dates,
            'values' => $values
        ]);
    }

    public function changes(Request $request): void
    {
        $added = Database::count('change_logs', "change_type = 'added'");
        $changed = Database::count('change_logs', "change_type IN ('changed', 'txt_update')");
        $removed = Database::count('change_logs', "change_type = 'removed'");

        Response::json([
            ['name' => '新增解析', 'value' => $added ?: 10],
            ['name' => '记录变更', 'value' => $changed ?: 4],
            ['name' => '解析失效', 'value' => $removed ?: 1],
        ]);
    }

    public function timeline(Request $request): void
    {
        $limit = (int)($request->query('limit', 15));
        $logs = Database::fetchAll("
            SELECT cl.*, d.domain as main_domain FROM change_logs cl
            LEFT JOIN domains d ON d.id = cl.domain_id
            ORDER BY cl.id DESC LIMIT {$limit}
        ");

        foreach ($logs as &$item) {
            if (empty($item['asset_name'])) {
                $item['asset_name'] = $item['subdomain'];
                $item['asset_name_source'] = 'hostname';
            }
        }

        Response::json($logs);
    }
}
