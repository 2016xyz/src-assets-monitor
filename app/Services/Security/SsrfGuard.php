<?php

namespace App\Services\Security;

class SsrfGuard
{
    /**
     * 校验外部 Webhook 或目标 URL 是否安全，阻断 SSRF 内网嗅探与 DNS Rebinding 攻击
     */
    public static function isSafeUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return false; // 严禁 file://, gopher://, dict://, php:// 等危险伪协议
        }

        $host = strtolower($parts['host']);

        // 1. 阻断本地回环与常见内部别名
        if ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1' || $host === '0.0.0.0') {
            return false;
        }

        // 2. 阻断云服务器元数据服务 (AWS/GCP/Alibaba Cloud/Azure IMDS)
        if ($host === '169.254.169.254' || str_ends_with($host, '.internal') || str_ends_with($host, '.local')) {
            return false;
        }

        // 3. 若直接输入的是 IPv4/IPv6 地址，检验是否属于私有内网或保留网段
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            if (!filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return false; // 命中 10.x.x.x, 172.16.x.x, 192.168.x.x 等私有网段
            }
        } else {
            // 4. 若为域名形式，执行 DNS 预解析校验底层真实 IP，防范 DNS Rebinding / 动态映射回内网
            $resolvedIp = gethostbyname($host);
            if ($resolvedIp && $resolvedIp !== $host) {
                if ($resolvedIp === '127.0.0.1' || $resolvedIp === '0.0.0.0' || $resolvedIp === '169.254.169.254') {
                    return false;
                }
                if (!filter_var($resolvedIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return false;
                }
            }
        }

        return true;
    }
}
