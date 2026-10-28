<?php

namespace App\Services\Proxy;

use App\Core\Crypto;

class DoHProxyClient
{
    private array $dohUpstreams = [
        'https://dns.google/resolve',
        'https://cloudflare-dns.com/dns-query'
    ];

    private CircuitBreaker $circuitBreaker;

    public function __construct(CircuitBreaker $cb)
    {
        $this->circuitBreaker = $cb;
    }

    /**
     * 经代理执行 DoH 解析
     * @param string $domain 如 api.target.com
     * @param string $type 记录类型 (A, AAAA, CNAME, TXT, MX)
     * @param array|null $proxy 代理节点数据 [protocol, host, port, auth_user, auth_pass_encrypted]
     */
    public function resolve(string $domain, string $type = 'A', ?array $proxy = null): array
    {
        $startTime = microtime(true);
        $upstream = $this->dohUpstreams[array_rand($this->dohUpstreams)];
        $url = $upstream . '?name=' . urlencode($domain) . '&type=' . urlencode($type);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 6);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 4);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/dns-json',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) SRC-Monitor/1.0'
        ]);

        if ($proxy) {
            $this->applyProxyToCurl($ch, $proxy);
        }

        $response = curl_exec($ch);
        $err = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $duration = (int)((microtime(true) - $startTime) * 1000);

        if ($err || $httpCode !== 200) {
            $errorMsg = $err ?: "DoH Upstream HTTP {$httpCode}";
            if ($proxy) {
                $this->circuitBreaker->recordFailure($proxy['id'], $errorMsg);
            }
            return [
                'status'     => 'fail',
                'error'      => $errorMsg,
                'records'    => [],
                'latency_ms' => $duration
            ];
        }

        $json = json_decode($response, true);
        $answers = [];
        if (!empty($json['Answer'])) {
            foreach ($json['Answer'] as $ans) {
                $answers[] = [
                    'name' => rtrim($ans['name'], '.'),
                    'type' => $type,
                    'data' => trim($ans['data'], '"'),
                    'ttl'  => $ans['TTL'] ?? 300
                ];
            }
        }

        if ($proxy) {
            $this->circuitBreaker->recordSuccess($proxy['id'], $duration);
        }

        return [
            'status'     => 'ok',
            'records'    => $answers,
            'latency_ms' => $duration
        ];
    }

    /**
     * 将代理参数注入 cURL 句柄
     */
    private function applyProxyToCurl($ch, array $proxy): void
    {
        $proto = strtolower($proxy['protocol'] ?? 'http');
        $host = $proxy['host'];
        $port = (int)$proxy['port'];

        $proxyType = CURLPROXY_HTTP;
        if ($proto === 'https') {
            $proxyType = CURLPROXY_HTTPS;
        } elseif ($proto === 'socks5') {
            $proxyType = CURLPROXY_SOCKS5;
        } elseif ($proto === 'socks5h') {
            // SOCKS5 远程 DNS 解析
            $proxyType = CURLPROXY_SOCKS5_HOSTNAME;
        }

        curl_setopt($ch, CURLOPT_PROXYTYPE, $proxyType);
        curl_setopt($ch, CURLOPT_PROXY, "{$host}:{$port}");

        if (!empty($proxy['auth_user'])) {
            $pass = !empty($proxy['auth_pass_encrypted']) ? Crypto::decrypt($proxy['auth_pass_encrypted']) : '';
            curl_setopt($ch, CURLOPT_PROXYUSERPWD, "{$proxy['auth_user']}:{$pass}");
        }
    }
}
