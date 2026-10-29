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
        'sched.tdnsv8.com',
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
     * 判断两个 IP 集合是否存在交集 (Jaccard 重叠判定)
     * 例如一次返回 [211.93.211.158, 36.35.39.162]，另一次返回 [36.35.39.162, 42.236.90.50]，存在重叠节点说明为同一个 CDN 轮换池
     */
    public static function hasIpOverlap(string $ipList1, string $ipList2): bool
    {
        $arr1 = array_filter(array_map('trim', explode(',', $ipList1)));
        $arr2 = array_filter(array_map('trim', explode(',', $ipList2)));

        if (empty($arr1) || empty($arr2)) {
            return false;
        }

        $intersect = array_intersect($arr1, $arr2);
        return !empty($intersect);
    }

    /**
     * 综合判断该解析变化是否属于 CDN 内部的良性 Anycast / GSLB 节点轮换调度
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

        // 1. 如果该子域名直接或间接挂载在知名 CDN 之下 (Cloudflare / EdgeOne / 腾讯CDN / 阿里CDN 等)
        // 其下属多节点 IP 轮换完全属于边缘 CDN 动态健康调度，直接静默放行！
        if ($isManagedByCdn) {
            return true;
        }

        // 2. 如果新旧值或 CNAME 链包含知名 CDN 特征
        if (self::isCdnCname($cnameChain) || self::isCdnCname($oldVal) || self::isCdnCname($newVal)) {
            return true;
        }

        // 3. 多 IP 节点调度池重叠判定：如果新旧两批 IP 存在交集节点，说明是在同一个 CDN 节点池内轮询
        if (self::hasIpOverlap($oldVal, $newVal)) {
            return true;
        }

        // 4. 如果新旧 IP 均属于 Cloudflare 官方网段
        $oldIps = array_filter(array_map('trim', explode(',', $oldVal)));
        $newIps = array_filter(array_map('trim', explode(',', $newVal)));

        $allOldCf = !empty($oldIps);
        foreach ($oldIps as $ip) {
            if (!self::isCloudflareIp($ip)) {
                $allOldCf = false;
                break;
            }
        }

        $allNewCf = !empty($newIps);
        foreach ($newIps as $ip) {
            if (!self::isCloudflareIp($ip)) {
                $allNewCf = false;
                break;
            }
        }

        if ($allOldCf && $allNewCf) {
            return true;
        }

        // 5. 同一 /24 子网下的 Anycast 轮换
        if (count($oldIps) === 1 && count($newIps) === 1) {
            if (self::isSameSubnet($oldIps[0], $newIps[0], 24)) {
                return true;
            }
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
