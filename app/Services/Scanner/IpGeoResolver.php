<?php

namespace App\Services\Scanner;

use App\Core\Cache;

class IpGeoResolver
{
    /**
     * 解析 IP 归属地与网络运营商 (内置 Cloudflare/私有IP直出与高效本地缓存)
     */
    public static function resolve(string $ip, ?array $proxy = null): array
    {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return [
                'ip'          => $ip,
                'country'     => '未知',
                'region'      => '',
                'city'        => '',
                'isp'         => '非有效IPv4',
                'location'    => '未知网络',
                'is_cdn'      => false,
                'cdn_vendor'  => null
            ];
        }

        // 1. 私有保留地址识别
        if (self::isPrivateIp($ip)) {
            return [
                'ip'         => $ip,
                'country'    => '局域网',
                'region'     => '内网',
                'city'       => '私有地址',
                'isp'        => 'RFC1918 私有保留',
                'location'   => '局域网 / 内网保留地址',
                'is_cdn'     => false,
                'cdn_vendor' => null
            ];
        }

        // 2. Cloudflare Anycast IP 快速直出 (免外部网络请求，毫秒级响应)
        if (CdnDriftFilter::isCloudflareIp($ip)) {
            return [
                'ip'         => $ip,
                'country'    => '全球 Anycast',
                'region'     => 'Cloudflare CDN',
                'city'       => '边缘加速节点',
                'isp'        => 'Cloudflare, Inc. (AS13335)',
                'location'   => 'Cloudflare 全球 Anycast 边缘节点',
                'is_cdn'     => true,
                'cdn_vendor' => 'Cloudflare'
            ];
        }

        // 3. 检查持久化或内存缓存 (缓存 7 天)
        $cacheKey = 'ipgeo_' . md5($ip);
        $cached = Cache::get($cacheKey);
        if ($cached && is_array($cached)) {
            return $cached;
        }

        // 4. 外部轻量 IP-API 接口查询 (带 2.5s 短超时与回退机制)
        $geo = self::fetchFromApi($ip, $proxy);
        Cache::set($cacheKey, $geo, 604800);

        return $geo;
    }

    private static function isPrivateIp(string $ip): bool
    {
        return !filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    private static function fetchFromApi(string $ip, ?array $proxy): array
    {
        $default = [
            'ip'         => $ip,
            'country'    => '中国',
            'region'     => '',
            'city'       => '',
            'isp'        => '通用网络接入商',
            'location'   => '互联网公网地址',
            'is_cdn'     => false,
            'cdn_vendor' => null
        ];

        // 优先使用 ip-api.com 中文接口
        $url = "http://ip-api.com/json/{$ip}?lang=zh-CN&fields=status,message,country,regionName,city,isp,as,org";
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_USERAGENT, 'SRC-Assets-GeoProbe/1.2');

        if ($proxy) {
            curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");
        }

        $res = curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);

        if (!$err && $res) {
            $data = json_decode($res, true);
            if (isset($data['status']) && $data['status'] === 'success') {
                $country = $data['country'] ?? '';
                $region = $data['regionName'] ?? '';
                $city = $data['city'] ?? '';
                $isp = $data['isp'] ?? ($data['org'] ?? '公网网络');

                $locParts = array_filter([$country, $region, $city]);
                $location = implode(' · ', array_unique($locParts));

                // 识别云厂商与知名 CDN
                $cdnVendor = null;
                $isCdn = false;
                $ispLower = strtolower($isp . ' ' . ($data['as'] ?? ''));

                if (str_contains($ispLower, 'tencent') || str_contains($ispLower, 'dnse2') || str_contains($ispLower, 'edgeone')) {
                    $cdnVendor = '腾讯云 / EdgeOne';
                    $isCdn = true;
                } elseif (str_contains($ispLower, 'alibaba') || str_contains($ispLower, 'aliyun')) {
                    $cdnVendor = '阿里云 / 阿里CDN';
                } elseif (str_contains($ispLower, 'huawei')) {
                    $cdnVendor = '华为云';
                } elseif (str_contains($ispLower, 'amazon') || str_contains($ispLower, 'aws')) {
                    $cdnVendor = 'Amazon AWS';
                } elseif (str_contains($ispLower, 'cloudflare')) {
                    $cdnVendor = 'Cloudflare';
                    $isCdn = true;
                }

                return [
                    'ip'         => $ip,
                    'country'    => $country,
                    'region'     => $region,
                    'city'       => $city,
                    'isp'        => $isp,
                    'location'   => $location ?: '未知地区',
                    'is_cdn'     => $isCdn,
                    'cdn_vendor' => $cdnVendor
                ];
            }
        }

        return $default;
    }
}
