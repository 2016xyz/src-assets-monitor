<?php

namespace App\Services\Notifier;

use App\Core\Database;
use App\Services\Proxy\ProxyScheduler;

class NotificationManager
{
    private array $notifiers = [];
    private ProxyScheduler $scheduler;

    public const SOURCE_LABELS = [
        'alias'       => '自定义',
        'http_title'  => '网页标题',
        'http_server' => '服务器标识',
        'cname'       => 'CNAME 目标',
        'ptr'         => '反查名称',
        'hostname'    => '未识别'
    ];

    public function __construct(ProxyScheduler $scheduler)
    {
        $this->scheduler = $scheduler;
        $this->notifiers = [
            'wecom' => new WeComNotifier(),
            'email' => new EmailNotifier(),
        ];
    }

    public function dispatchBatch(array $domain, array $changes): void
    {
        if (empty($changes)) return;

        // 获取该域名绑定的通知渠道
        $channels = Database::fetchAll("
            SELECT nc.* FROM notify_channels nc
            INNER JOIN domain_channel dc ON dc.channel_id = nc.id
            WHERE dc.domain_id = ? AND nc.status = 1
        ", [$domain['id']]);

        if (empty($channels)) {
            $channels = Database::fetchAll("SELECT * FROM notify_channels WHERE status = 1");
        }

        if (empty($channels)) return;

        $title = "【SRC资产异动】主域名 {$domain['domain']} 发现 " . count($changes) . " 条解析变动";

        // 单条变动与多条聚合分别渲染
        $markdownContent = $this->formatMarkdown($domain['domain'], $changes);
        $emailContent = $this->formatEmailBody($domain['domain'], $changes);

        foreach ($channels as $chan) {
            if ($this->isSilenced($chan)) {
                continue;
            }

            $type = $chan['type'] ?? 'wecom';
            $notifier = $this->notifiers[$type] ?? $this->notifiers['wecom'];
            $config = json_decode($chan['config'] ?? '{}', true) ?: [];

            // 专属出口代理 (若配置)
            $proxy = null;
            if (!empty($chan['proxy_group_id'])) {
                $proxy = $this->scheduler->selectProxy((int)$chan['proxy_group_id']);
            }

            $contentToSend = ($type === 'email') ? $emailContent : $markdownContent;

            // 最多 3 次指数退避重试
            $success = false;
            $resData = '';
            for ($attempt = 1; $attempt <= 3; $attempt++) {
                $res = $notifier->send($config, $title, $contentToSend, $proxy);
                if ($res['success']) {
                    $success = true;
                    $resData = $res['response'] ?? 'ok';
                    break;
                }
                sleep($attempt);
            }

            Database::insert('notify_logs', [
                'channel_id'    => $chan['id'],
                'domain_id'     => $domain['id'],
                'title'         => $title,
                'content'       => $contentToSend,
                'status'        => $success ? 1 : 0,
                'retry_count'   => $attempt - 1,
                'response_data' => substr($resData, 0, 500),
                'created_at'    => date('Y-m-d H:i:s')
            ]);
        }
    }

    /**
     * Markdown 格式渲染 (包含资产名称、来源与聚合规则)
     */
    public function formatMarkdown(string $domain, array $changes): string
    {
        $tags = [
            'added'      => '🆕 新增解析',
            'changed'    => '🔄 解析变更',
            'removed'    => '❌ 解析失效',
            'txt_update' => '⚠️ 记录变动'
        ];

        $lines = [];
        $lines[] = "### 资产监控告警";
        $lines[] = "> 监测目标: `{$domain}`";
        $lines[] = "> 捕获时间: " . date('Y-m-d H:i:s');
        $lines[] = "";

        if (count($changes) === 1) {
            // 单条通知
            $item = $changes[0];
            $displayName = $this->resolveDisplayName($item['asset_name'] ?? '', $item['subdomain']);
            $sourceName = self::SOURCE_LABELS[$item['asset_name_source'] ?? 'hostname'] ?? '未识别';
            $changeTag = $tags[$item['change_type']] ?? $item['change_type'];

            $lines[] = "- **资产名称**: {$displayName}";
            $lines[] = "- **子域名**: `{$item['subdomain']}`";
            $lines[] = "- **变更类型**: {$changeTag}";
            $lines[] = "- **解析记录**: `" . ($item['new_value'] ?: 'NXDOMAIN (失效)') . "`";
            $lines[] = "- **名称来源**: {$sourceName}";
        } else {
            // 同轮多条聚合通知
            $lines[] = "**变动明细聚合清单**:";
            foreach ($changes as $item) {
                $displayName = $this->resolveDisplayName($item['asset_name'] ?? '', $item['subdomain']);
                $changeTag = $tags[$item['change_type']] ?? $item['change_type'];
                $lines[] = "• **{$displayName}**（`{$item['subdomain']}`）— {$changeTag}";
            }
        }

        $lines[] = "";
        $lines[] = "> 来源：SRC 资产检测站";
        return implode("\n", $lines);
    }

    /**
     * 邮件文本与模板渲染 (遵循题目格式与回退规则)
     */
    public function formatEmailBody(string $domain, array $changes): string
    {
        $templateFn = require __DIR__ . '/templates/alert_email.php';
        $changeLabels = [
            'added'      => '新增资产',
            'changed'    => '解析记录变更',
            'removed'    => '解析失效 (NXDOMAIN)',
            'txt_update' => 'TXT记录变动'
        ];

        if (count($changes) === 1) {
            $item = $changes[0];
            return $templateFn([
                'asset_name'        => $item['asset_name'] ?? '',
                'subdomain'         => $item['subdomain'],
                'domain'            => $domain,
                'change_type'       => $changeLabels[$item['change_type']] ?? $item['change_type'],
                'new_value'         => $item['new_value'] ?: '失效 (NXDOMAIN)',
                'asset_name_source' => $item['asset_name_source'] ?? 'hostname',
                'time'              => date('Y-m-d H:i:s')
            ]);
        }

        // 多条聚合邮件
        $lines = [];
        $lines[] = "资产监控告警 (聚合推送)";
        $lines[] = "────────────────";
        $lines[] = "主域名：  {$domain}";
        $lines[] = "发现时间： " . date('Y-m-d H:i:s');
        $lines[] = "变更数量： " . count($changes) . " 条";
        $lines[] = "────────────────";
        $lines[] = "资产变动明细：";
        foreach ($changes as $item) {
            $displayName = $this->resolveDisplayName($item['asset_name'] ?? '', $item['subdomain']);
            $changeTag = $changeLabels[$item['change_type']] ?? $item['change_type'];
            $lines[] = "• {$displayName}（{$item['subdomain']}）— {$changeTag}";
        }
        $lines[] = "────────────────";
        $lines[] = "来源：SRC 资产检测站";
        return implode("\n", $lines);
    }

    private function resolveDisplayName(?string $name, string $subdomain): string
    {
        if (empty($name) || $name === $subdomain) {
            return "{$subdomain} (名称未识别)";
        }
        return $name;
    }

    private function isSilenced(array $chan): bool
    {
        if (empty($chan['silence_start']) || empty($chan['silence_end'])) {
            return false;
        }
        $now = date('H:i:s');
        return ($now >= $chan['silence_start'] && $now <= $chan['silence_end']);
    }
}
