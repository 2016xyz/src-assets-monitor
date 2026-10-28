<?php

namespace App\Services\Scanner;

use App\Core\Cache;

class ResolverPool
{
    private array $defaultResolvers = [
        '1.1.1.1',        // Cloudflare
        '1.0.0.1',        // Cloudflare
        '8.8.8.8',        // Google
        '8.8.4.4',        // Google
        '9.9.9.9',        // Quad9
        '208.67.222.222', // OpenDNS
        '208.67.220.220', // OpenDNS
        '223.5.5.5',      // AliDNS
        '223.6.6.6',      // AliDNS
        '119.29.29.29',   // DNSPod
        '114.114.114.114' // 114DNS
    ];

    private array $healthyResolvers = [];

    /**
     * 探测解析器可用性并剔除失效节点
     */
    public function probeAndFilter(int $timeoutMs = 1500): array
    {
        $healthy = [];

        foreach ($this->defaultResolvers as $resolver) {
            // 通过 UDP 53 发起轻量测试
            if ($this->pingResolver($resolver, $timeoutMs)) {
                $healthy[] = $resolver;
            }
        }

        // 至少保留 2 个兜底
        if (empty($healthy)) {
            $healthy = ['1.1.1.1', '8.8.8.8'];
        }

        $this->healthyResolvers = $healthy;
        return $healthy;
    }

    /**
     * 轮询选择一个健康解析器并应用限速 (单解析器不超过 5 QPS)
     */
    public function getNextResolver(): string
    {
        if (empty($this->healthyResolvers)) {
            $this->healthyResolvers = $this->defaultResolvers;
        }

        $idxKey = 'resolver_pool_rr_idx';
        $idx = (int)Cache::get($idxKey, 0);
        $resolver = $this->healthyResolvers[$idx % count($this->healthyResolvers)];
        Cache::set($idxKey, $idx + 1, 3600);

        // 单解析器限流微延时
        $rateKey = 'resolver_rate_' . md5($resolver) . '_' . date('YmdHis');
        $qps = (int)Cache::get($rateKey, 0);
        if ($qps >= 5) {
            usleep(200000); // 200ms
        }
        Cache::set($rateKey, $qps + 1, 2);

        return $resolver;
    }

    /**
     * 探查单个 DNS 服务器连通性
     */
    private function pingResolver(string $ip, int $timeoutMs): bool
    {
        $socket = @fsockopen("udp://{$ip}", 53, $errno, $errstr, $timeoutMs / 1000);
        if (!$socket) {
            return false;
        }

        // 构造极简 A 记录 DNS 查询包: example.com
        $query = "\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" .
                 "\x07example\x03com\x00\x00\x01\x00\x01";

        stream_set_timeout($socket, 0, $timeoutMs * 1000);
        @fwrite($socket, $query);
        $response = @fread($socket, 512);
        fclose($socket);

        return !empty($response) && strlen($response) > 12;
    }

    public function getHealthyList(): array
    {
        return !empty($this->healthyResolvers) ? $this->healthyResolvers : $this->defaultResolvers;
    }
}
