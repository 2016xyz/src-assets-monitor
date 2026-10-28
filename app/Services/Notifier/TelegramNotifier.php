<?php

namespace App\Services\Notifier;

class TelegramNotifier implements NotifierInterface
{
    public function send(array $config, string $title, string $content, ?array $proxy = null): array
    {
        $botToken = trim($config['bot_token'] ?? '');
        $chatId = trim($config['chat_id'] ?? '');

        if (!$botToken || !$chatId) {
            return ['success' => false, 'error' => '未配置 Telegram Bot Token 或 Chat ID'];
        }

        $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
        $text = "<b>{$title}</b>\n\n" . htmlspecialchars($content, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        $payload = [
            'chat_id'    => $chatId,
            'text'       => $text,
            'parse_mode' => 'HTML'
        ];

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($payload));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

        if ($proxy) {
            curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");
        }

        $res = curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);

        if ($err) {
            return ['success' => false, 'error' => "Telegram 接口连接失败: {$err} (若服务器在国内需绑定海外代理出口)"];
        }

        $json = json_decode($res, true);
        $ok = !empty($json['ok']);
        return [
            'success'  => $ok,
            'response' => $res,
            'error'    => $ok ? null : ($json['description'] ?? 'Telegram 推送失败')
        ];
    }
}
