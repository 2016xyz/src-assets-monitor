<?php

namespace App\Services\Notifier;

class WeComNotifier implements NotifierInterface
{
    public function send(array $config, string $title, string $content, ?array $proxy = null): array
    {
        $webhook = $config['webhook_url'] ?? '';
        if (!$webhook) {
            return ['success' => false, 'error' => '未配置企业微信 Webhook'];
        }

        $payload = [
            'msgtype'  => 'markdown',
            'markdown' => [
                'content' => "### {$title}\n\n{$content}"
            ]
        ];

        return $this->httpPost($webhook, $payload, $proxy);
    }

    private function httpPost(string $url, array $data, ?array $proxy): array
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data, JSON_UNESCAPED_UNICODE));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_TIMEOUT, 8);

        if ($proxy) {
            curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");
        }

        $res = curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);

        if ($err) {
            return ['success' => false, 'error' => $err];
        }

        $json = json_decode($res, true);
        $ok = isset($json['errcode']) && $json['errcode'] === 0;
        return ['success' => $ok, 'response' => $res, 'error' => $ok ? null : ($json['errmsg'] ?? '发送失败')];
    }
}
