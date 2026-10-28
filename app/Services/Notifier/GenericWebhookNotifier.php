<?php

namespace App\Services\Notifier;

use App\Services\Security\SsrfGuard;

class GenericWebhookNotifier implements NotifierInterface
{
    public function send(array $config, string $title, string $content, ?array $proxy = null): array
    {
        $url = trim($config['webhook_url'] ?? '');
        if (!$url) {
            return ['success' => false, 'error' => '未配置通用 Webhook 接收端点 URL'];
        }

        if (!SsrfGuard::isSafeUrl($url)) {
            return ['success' => false, 'error' => '安全阻断: 检测到非法的 Webhook 目标地址'];
        }

        $payload = [
            'event'     => 'asset_change_alert',
            'title'     => $title,
            'content'   => $content,
            'timestamp' => date('c')
        ];

        $headers = ['Content-Type: application/json; charset=utf-8'];
        if (!empty($config['custom_headers'])) {
            $custom = is_array($config['custom_headers']) ? $config['custom_headers'] : json_decode($config['custom_headers'], true);
            if (is_array($custom)) {
                foreach ($custom as $k => $v) {
                    $headers[] = "{$k}: {$v}";
                }
            }
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload, JSON_UNESCAPED_UNICODE));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_TIMEOUT, 8);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

        if ($proxy) {
            curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");
        }

        $res = curl_exec($ch);
        $err = curl_error($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($err) {
            return ['success' => false, 'error' => "Webhook 投递异常: {$err}"];
        }

        $isOk = ($code >= 200 && $code < 300);
        return [
            'success'  => $isOk,
            'response' => "HTTP {$code}: " . substr($res, 0, 200),
            'error'    => $isOk ? null : "端点返回非 2xx 响应: HTTP {$code}"
        ];
    }
}
