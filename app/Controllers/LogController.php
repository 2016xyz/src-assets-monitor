<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;

class LogController
{
    /**
     * GET /api/v1/logs/tasks - 资产巡检任务历史列表 (带分页)
     */
    public function getTasks(Request $request): void
    {
        $page = max(1, (int)$request->query('page', 1));
        $pageSize = max(1, min(100, (int)$request->query('page_size', 15)));
        $offset = ($page - 1) * $pageSize;

        $status = $request->query('status');
        $domainId = (int)$request->query('domain_id');
        $kw = $request->query('keyword');

        $where = ["1=1"];
        $params = [];

        if ($status) {
            $where[] = "st.status = ?";
            $params[] = $status;
        }
        if ($domainId > 0) {
            $where[] = "st.domain_id = ?";
            $params[] = $domainId;
        }
        if ($kw) {
            $where[] = "(d.domain LIKE ? OR st.error_message LIKE ?)";
            $params[] = "%{$kw}%";
            $params[] = "%{$kw}%";
        }

        $whereSql = implode(' AND ', $where);
        $total = Database::count('scan_tasks st LEFT JOIN domains d ON d.id = st.domain_id', $whereSql, $params);

        $sql = "
            SELECT st.*, d.domain as target_domain
            FROM scan_tasks st
            LEFT JOIN domains d ON d.id = st.domain_id
            WHERE {$whereSql}
            ORDER BY st.id DESC LIMIT {$pageSize} OFFSET {$offset}
        ";
        $list = Database::fetchAll($sql, $params);

        Response::json([
            'list'      => $list,
            'total'     => $total,
            'page'      => $page,
            'page_size' => $pageSize
        ]);
    }

    /**
     * GET /api/v1/logs/stages - 任务执行详细阶段流水日志 (带分页与级别筛选)
     */
    public function getStages(Request $request): void
    {
        $page = max(1, (int)$request->query('page', 1));
        $pageSize = max(1, min(200, (int)$request->query('page_size', 20)));
        $offset = ($page - 1) * $pageSize;

        $taskId = (int)$request->query('task_id');
        $level = $request->query('level');
        $stage = $request->query('stage');
        $kw = $request->query('keyword');

        $where = ["1=1"];
        $params = [];

        if ($taskId > 0) {
            $where[] = "stl.task_id = ?";
            $params[] = $taskId;
        }
        if ($level) {
            $where[] = "stl.level = ?";
            $params[] = $level;
        }
        if ($stage) {
            $where[] = "stl.stage = ?";
            $params[] = $stage;
        }
        if ($kw) {
            $where[] = "(stl.message LIKE ? OR d.domain LIKE ?)";
            $params[] = "%{$kw}%";
            $params[] = "%{$kw}%";
        }

        $whereSql = implode(' AND ', $where);
        $total = Database::count('scan_task_logs stl LEFT JOIN scan_tasks st ON st.id = stl.task_id LEFT JOIN domains d ON d.id = st.domain_id', $whereSql, $params);

        $sql = "
            SELECT stl.*, st.domain_id, d.domain as target_domain
            FROM scan_task_logs stl
            LEFT JOIN scan_tasks st ON st.id = stl.task_id
            LEFT JOIN domains d ON d.id = st.domain_id
            WHERE {$whereSql}
            ORDER BY stl.id DESC LIMIT {$pageSize} OFFSET {$offset}
        ";
        $list = Database::fetchAll($sql, $params);

        Response::json([
            'list'      => $list,
            'total'     => $total,
            'page'      => $page,
            'page_size' => $pageSize
        ]);
    }
}
