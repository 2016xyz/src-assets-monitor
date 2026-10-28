<?php

namespace App\Services\Notifier;

use App\Services\Security\SsrfGuard;

class DingTalkNotifier implements NotifierInterface
{
    public function send(array $config, string $title, string $content, ?array $proxy = null): array
    {
        $webhook = trim($config['webhook_url'] ?? '');
        if (!$webhook) {
            return ['success' => false, 'error' => '未配置钉钉机器人 Webhook 地址'];
        }

        if (!SsrfGuard::isSafeUrl($webhook)) {
            return ['success' => false, 'error' => '安全阻断: 检测到非法的 Webhook 目标地址'];
        }

        // 若配置了加签密钥 Secret，进行 HMAC-SHA256 签名计算
        $secret = trim($config['secret'] ?? '');
        $finalUrl = $webhook;
        if ($secret) {
            $timestamp = (int)(microtime(true) * 1000);
            $stringToSign = "{$timestamp}\n{$secret}";
            $sign = urlencode(base64_encode(hash_hmac('sha256', $stringToSign, $secret, true)));
            $connector = str_contains($webhook, '?') ? '&' : '?';
            $finalUrl = "{$webhook}{$connector}timestamp={$timestamp}&sign={$sign}";
        }

        $payload = [
            'msgtype' => 'markdown',
            'markdown' => [
                'title' => $title,
                'text'  => "### {$title}\n\n{$content}"
            ]
        ];

        return $this->httpPost($finalUrl, $payload, $proxy);
    }

    private function httpPost(string $url, array $data, ?array $proxy): array
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data, JSON_UNESCAPED_UNICODE));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json; charset=utf-8']);
        curl_setopt($ch, CURLOPT_TIMEOUT, 8);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

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
        return [
            'success'  => $ok,
            'response' => $res,
            'error'    => $ok ? null : ($json['errmsg'] ?? '钉钉机器人推送失败')
        ];
    }
}
