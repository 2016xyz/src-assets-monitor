<?php

namespace App\Services\Security;

class SsrfGuard
{
    /**
     * 校验外部 Webhook 或目标 URL 是否安全，阻断 SSRF 内网嗅探
     */
    public static function isSafeUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return false; // 严禁 file://, gopher://, dict://, php:// 等伪协议
        }

        $host = strtolower($parts['host']);

        // 阻断本地回环与常见内部别名
        if ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1' || $host === '0.0.0.0') {
            return false;
        }

        // 阻断云服务器元数据服务 (AWS/GCP/Alibaba Cloud/Azure IMDS)
        if ($host === '169.254.169.254' || str_ends_with($host, '.internal')) {
            return false;
        }

        // 若直接输入的是 IP 地址，检验是否属于私有内网网段
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            if (!filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return false; // 命中 10.x.x.x, 172.16.x.x, 192.168.x.x 等私有网段
            }
        }

        return true;
    }
}
