<?php

namespace App\Services\Scanner;

class CdnDriftFilter
{
    /**
     * 官方权威 Cloudflare IPv4 CIDR 网段列表
     */
    private const CLOUDFLARE_CIDRS = [
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22',
    ];

    /**
     * 常见主流 CDN 平台 CNAME 标志性域名特征
     */
    private const CDN_CNAME_PATTERNS = [
        'pages.dev',
        'cdn.cloudflare.net',
        'cloudflare.com',
        'eo.dnse2.com',
        'eo.dnse3.com',
        'dnsv1.com',
        'dnsv1.com.cn',
        'tdnsv8.com',
        'qcloudcdn.com',
        'tcdn.qq.com',
        'kunlun.com',
        'alicdn.com',
        'wscdns.com',
        'cdngslb.com',
        'yunjiasu-cdn.net',
        'jomodns.com',
        'hwclouds-dns.com',
        'cloudcdn.net',
        'akamaiedge.net',
        'edgekey.net',
        'akamaitechnologies.com',
        'fastly.net',
        'fastlylb.net',
        'cloudfront.net'
    ];

    /**
     * 判断某个 CNAME 目标或 CNAME 链是否属于知名 CDN 托管
     */
    public static function isCdnCname(?string $target): bool
    {
        if (empty($target)) return false;
        $t = strtolower(trim($target, '. '));
        foreach (self::CDN_CNAME_PATTERNS as $pattern) {
            if (str_contains($t, $pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 综合判断该解析变化是否属于 CDN 内部的良性 Anycast / GeoDNS 动态调度
     */
    public static function isBenignCdnDrift(
        ?string $oldValue,
        ?string $newValue,
        bool $isManagedByCdn = false,
        ?string $cnameChain = null
    ): bool {
        if (empty($oldValue) || empty($newValue)) {
            return false;
        }

        $oldVal = trim($oldValue);
        $newVal = trim($newValue);

        if ($oldVal === $newVal) {
            return true;
        }

        // 1. 如果该子域名挂载在 CDN 之下 (存在指向 Cloudflare/EdgeOne 等的 CNAME 记录)
        // 其下属 A 记录由不同递归 DNS 查询出的节点 IP 切换，均属于 CDN 正常边缘分发
        if ($isManagedByCdn) {
            return true;
        }

        // 2. 如果存在 CNAME 链并命中了 CDN 特征
        if (self::isCdnCname($cnameChain) || self::isCdnCname($oldValue) || self::isCdnCname($newValue)) {
            return true;
        }

        // 3. 如果新旧 IP 均属于 Cloudflare 官方网段
        if (self::isCloudflareIp($oldVal) && self::isCloudflareIp($newVal)) {
            return true;
        }

        // 4. 同一 /24 子网下的 Anycast 轮换
        if (self::isSameSubnet($oldVal, $newVal, 24)) {
            return true;
        }

        return false;
    }

    /**
     * 检查给定的 IP 是否属于 Cloudflare 官方网段
     */
    public static function isCloudflareIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $longIp = ip2long($ip);
        if ($longIp === false) {
            return false;
        }

        foreach (self::CLOUDFLARE_CIDRS as $cidr) {
            [$subnet, $mask] = explode('/', $cidr);
            $longSubnet = ip2long($subnet);
            $maskInt = ~((1 << (32 - (int)$mask)) - 1);

            if (($longIp & $maskInt) === ($longSubnet & $maskInt)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 辅助判断两个 IPv4 是否处于同一个 /24 子网网段
     */
    public static function isSameSubnet(string $ip1, string $ip2, int $mask = 24): bool
    {
        if (!filter_var($ip1, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
            !filter_var($ip2, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $l1 = ip2long($ip1);
        $l2 = ip2long($ip2);
        if ($l1 === false || $l2 === false) {
            return false;
        }

        $maskInt = ~((1 << (32 - $mask)) - 1);
        return ($l1 & $maskInt) === ($l2 & $maskInt);
    }
}
