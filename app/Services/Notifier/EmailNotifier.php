<?php

namespace App\Services\Notifier;

class EmailNotifier implements NotifierInterface
{
    public function send(array $config, string $title, string $content, ?array $proxy = null): array
    {
        $host = $config['smtp_host'] ?? '';
        $port = (int)($config['smtp_port'] ?? 465);
        $user = $config['smtp_user'] ?? '';
        $pass = $config['smtp_pass'] ?? '';
        $to = $config['to_email'] ?? $user;

        if (!$host || !$user) {
            return ['success' => false, 'error' => 'SMTP 主机或账号配置缺失'];
        }

        try {
            $prefix = ($port == 465) ? 'ssl://' : '';
            $socket = @fsockopen($prefix . $host, $port, $errno, $errstr, 5);
            if (!$socket) {
                return ['success' => false, 'error' => "连接 SMTP 服务器失败: {$errstr} ({$errno})"];
            }

            $this->readResponse($socket);
            $this->sendCommand($socket, "EHLO {$host}");
            $this->sendCommand($socket, "AUTH LOGIN");
            $this->sendCommand($socket, base64_encode($user));
            $this->sendCommand($socket, base64_encode($pass));
            $this->sendCommand($socket, "MAIL FROM: <{$user}>");
            $this->sendCommand($socket, "RCPT TO: <{$to}>");
            $this->sendCommand($socket, "DATA");

            // 防注入：对邮件标题与内容进行严格 HTML 安全转义 (防邮件客户端 XSS 攻击)
            $safeTitle = htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $safeContent = nl2br(htmlspecialchars($content, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'));

            $headers = "From: SRC 资产检测站 <{$user}>\r\n" .
                       "To: <{$to}>\r\n" .
                       "Subject: =?UTF-8?B?" . base64_encode($title) . "?=\r\n" .
                       "MIME-Version: 1.0\r\n" .
                       "Content-Type: text/html; charset=UTF-8\r\n\r\n";

            $body = "<div style='font-family:sans-serif;line-height:1.6;color:#1e293b;'><h3>{$safeTitle}</h3><div style='background:#f8fafc;padding:16px;border-left:4px solid #3b82f6;'>{$safeContent}</div></div>\r\n.\r\n";

            fputs($socket, $headers . $body);
            $this->readResponse($socket);
            $this->sendCommand($socket, "QUIT");
            fclose($socket);

            return ['success' => true, 'error' => null];
        } catch (\Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    private function sendCommand($socket, string $cmd): string
    {
        // 防 SMTP CRLF 命令注入：剔除换行符
        $cleanCmd = str_replace(["\r", "\n"], '', $cmd);
        fputs($socket, $cleanCmd . "\r\n");
        return $this->readResponse($socket);
    }

    private function readResponse($socket): string
    {
        $res = '';
        while ($line = fgets($socket, 512)) {
            $res .= $line;
            if (isset($line[3]) && $line[3] === ' ') break;
        }
        return $res;
    }
}
