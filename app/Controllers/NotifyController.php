<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use App\Services\Notifier\EmailNotifier;
use App\Services\Notifier\WeComNotifier;

class NotifyController
{
    public function index(Request $request): void
    {
        $list = Database::fetchAll("SELECT * FROM notify_channels ORDER BY id DESC");
        foreach ($list as &$item) {
            $cfg = json_decode($item['config'] ?? '{}', true) ?: [];
            if (!empty($cfg['smtp_pass'])) {
                $cfg['smtp_pass'] = '••••••••';
            }
            $item['config_parsed'] = $cfg;
        }
        Response::json($list);
    }

    public function store(Request $request): void
    {
        $b = $request->input();
        if (empty($b['name']) || empty($b['type'])) {
            Response::error('请补全渠道名称与类型', 422);
        }

        $id = Database::insert('notify_channels', [
            'name'            => $b['name'],
            'type'            => $b['type'],
            'config'          => json_encode($b['config'] ?? [], JSON_UNESCAPED_UNICODE),
            'proxy_group_id'  => !empty($b['proxy_group_id']) ? (int)$b['proxy_group_id'] : null,
            'status'          => isset($b['status']) ? (int)$b['status'] : 1,
            'silence_start'   => $b['silence_start'] ?? null,
            'silence_end'     => $b['silence_end'] ?? null,
            'custom_template' => $b['custom_template'] ?? null,
            'created_at'      => date('Y-m-d H:i:s')
        ]);

        Response::json(['id' => $id], 0, '通知渠道已保存');
    }

    public function destroy(Request $request, $id): void
    {
        $id = (int)$id;
        Database::delete('notify_channels', 'id = ?', [$id]);
        Response::json(null, 0, '已删除');
    }

    public function testChannel(Request $request, $id): void
    {
        $id = (int)$id;
        $chan = Database::fetchOne("SELECT * FROM notify_channels WHERE id = ?", [$id]);
        if (!$chan) Response::error('渠道不存在', 404);

        $cfg = json_decode($chan['config'] ?? '{}', true) ?: [];
        $title = "【连通性测试】SRC 资产检测站 - " . date('H:i:s');
        $content = "您收到本条消息，表明告警渠道 [{$chan['name']}] 配置正确，网络通信畅通。";

        $notifier = match ($chan['type']) {
            'email' => new EmailNotifier(),
            default => new WeComNotifier(),
        };

        $res = $notifier->send($cfg, $title, $content);
        if ($res['success']) {
            Response::json($res, 0, '测试消息已成功送达目标端');
        } else {
            Response::error($res['error'] ?? '发送失败', 500);
        }
    }
}
