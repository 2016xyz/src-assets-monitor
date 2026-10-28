<?php

namespace App\Controllers;

use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use App\Services\Notifier\DingTalkNotifier;
use App\Services\Notifier\EmailNotifier;
use App\Services\Notifier\FeishuNotifier;
use App\Services\Notifier\GenericWebhookNotifier;
use App\Services\Notifier\TelegramNotifier;
use App\Services\Notifier\WeComNotifier;
use App\Services\Proxy\CircuitBreaker;
use App\Services\Proxy\ProxyRateLimiter;
use App\Services\Proxy\ProxyScheduler;

class NotifyController
{
    private array $notifiers = [];
    private ProxyScheduler $scheduler;

    public function __construct()
    {
        $this->scheduler = new ProxyScheduler(new CircuitBreaker(), new ProxyRateLimiter());
        $this->notifiers = [
            'wecom'    => new WeComNotifier(),
            'dingtalk' => new DingTalkNotifier(),
            'feishu'   => new FeishuNotifier(),
            'telegram' => new TelegramNotifier(),
            'email'    => new EmailNotifier(),
            'webhook'  => new GenericWebhookNotifier(),
        ];
    }

    public function index(Request $request): void
    {
        $list = Database::fetchAll("SELECT * FROM notify_channels ORDER BY id DESC");
        foreach ($list as &$item) {
            $cfg = json_decode($item['config'] ?? '{}', true) ?: [];
            if (!empty($cfg['smtp_pass'])) {
                $cfg['smtp_pass'] = '••••••••';
            }
            if (!empty($cfg['secret'])) {
                $cfg['secret'] = '••••••••';
            }
            if (!empty($cfg['bot_token'])) {
                $cfg['bot_token'] = substr($cfg['bot_token'], 0, 6) . '••••••••';
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

        $type = strtolower($b['type']);
        if (!isset($this->notifiers[$type])) {
            Response::error('暂不支持该渠道类型: ' . $type, 422);
        }

        $config = $b['config'] ?? [];

        $id = Database::insert('notify_channels', [
            'name'            => trim($b['name']),
            'type'            => $type,
            'config'          => json_encode($config, JSON_UNESCAPED_UNICODE),
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
        Database::delete('domain_channel', 'channel_id = ?', [$id]);
        Response::json(null, 0, '已删除');
    }

    public function testChannel(Request $request, $id): void
    {
        $id = (int)$id;
        $chan = Database::fetchOne("SELECT * FROM notify_channels WHERE id = ?", [$id]);
        if (!$chan) Response::error('渠道不存在', 404);

        $type = strtolower($chan['type'] ?? 'wecom');
        $notifier = $this->notifiers[$type] ?? $this->notifiers['wecom'];
        $cfg = json_decode($chan['config'] ?? '{}', true) ?: [];

        $title = "【连通性测试】SRC 资产检测站 - " . date('H:i:s');
        $content = "您收到本条消息，表明告警渠道 [{$chan['name']}] ({$type}) 配置正确，网络通信畅通。\n- 测试目标: `src.2016xlx.cn`\n- 测试时间: " . date('Y-m-d H:i:s');

        // 专属代理出口
        $proxy = null;
        if (!empty($chan['proxy_group_id'])) {
            $proxy = $this->scheduler->selectProxy((int)$chan['proxy_group_id']);
        }

        $res = $notifier->send($cfg, $title, $content, $proxy);
        if ($res['success']) {
            Response::json($res, 0, '测试消息已成功送达目标端');
        } else {
            Response::error($res['error'] ?? '发送失败，请检查配置参数与网络', 500);
        }
    }
}
