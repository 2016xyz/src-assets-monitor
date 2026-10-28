<?php

namespace App\Services\Notifier;

use App\Services\Security\SsrfGuard;

class FeishuNotifier implements NotifierInterface
{
    public function send(array $config, string $title, string $content, ?array $proxy = null): array
    {
        $webhook = trim($config['webhook_url'] ?? '');
        if (!$webhook) {
            return ['success' => false, 'error' => '未配置飞书机器人 Webhook 地址'];
        }

        if (!SsrfGuard::isSafeUrl($webhook)) {
            return ['success' => false, 'error' => '安全阻断: 检测到非法的 Webhook 目标地址'];
        }

        $payload = [
            'msg_type' => 'interactive',
            'card'     => [
                'header' => [
                    'title' => ['tag' => 'plain_text', 'content' => $title],
                    'template' => 'blue'
                ],
                'elements' => [
                    [
                        'tag'     => 'markdown',
                        'content' => $content
                    ]
                ]
            ]
        ];

        // 飞书签名算法
        $secret = trim($config['secret'] ?? '');
        if ($secret) {
            $timestamp = time();
            $stringToSign = "{$timestamp}\n{$secret}";
            $sign = base64_encode(hash_hmac('sha256', '', $stringToSign, true));
            $payload['timestamp'] = (string)$timestamp;
            $payload['sign'] = $sign;
        }

        return $this->httpPost($webhook, $payload, $proxy);
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
        $ok = (isset($json['code']) && $json['code'] === 0) || (isset($json['StatusCode']) && $json['StatusCode'] === 0);
        return [
            'success'  => $ok,
            'response' => $res,
            'error'    => $ok ? null : ($json['msg'] ?? '飞书机器人推送失败')
        ];
    }
}
