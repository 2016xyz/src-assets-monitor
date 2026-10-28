<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;

class SettingController
{
    public function getSettings(Request $request): void
    {
        $rows = Database::fetchAll("SELECT * FROM settings");
        $map = [];
        foreach ($rows as $r) {
            $val = $r['value'];
            $json = json_decode($val, true);
            $map[$r['key']] = ($json !== null && is_array($json)) ? $json : $val;
        }
        Response::json($map);
    }

    public function saveSetting(Request $request): void
    {
        $b = $request->input();
        $key = $b['key'] ?? '';
        $val = $b['value'] ?? null;

        if (!$key) Response::error('配置 Key 缺失', 422);

        $valStr = is_array($val) ? json_encode($val, JSON_UNESCAPED_UNICODE) : (string)$val;
        $ex = Database::fetchOne("SELECT id FROM settings WHERE `key` = ?", [$key]);
        if ($ex) {
            Database::update('settings', ['value' => $valStr], 'id = ?', [$ex['id']]);
        } else {
            Database::insert('settings', ['key' => $key, 'value' => $valStr]);
        }

        Response::json(null, 0, '配置已持久化');
    }

    public function auditLogs(Request $request): void
    {
        $page = max(1, (int)$request->query('page', 1));
        $pageSize = max(1, min(100, (int)$request->query('page_size', 20)));
        $offset = ($page - 1) * $pageSize;

        $total = Database::count('operation_logs');
        $list = Database::fetchAll("SELECT * FROM operation_logs ORDER BY id DESC LIMIT {$pageSize} OFFSET {$offset}");

        Response::json([
            'list'      => $list,
            'total'     => $total,
            'page'      => $page,
            'page_size' => $pageSize
        ]);
    }
}
