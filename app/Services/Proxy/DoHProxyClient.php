<?php

namespace App\Services\Proxy;

use App\Core\Crypto;

class DoHProxyClient
{
    private array $dohUpstreams = [
        'https://dns.alidns.com/resolve',
        'https://doh.pub/dns-query',
        'https://doh.360.cn/resolve',
        'https://cloudflare-dns.com/dns-query',
        'https://dns.google/resolve'
    ];

    private CircuitBreaker $circuitBreaker;

    public function __construct(CircuitBreaker $cb)
    {
        $this->circuitBreaker = $cb;
    }

    /**
     * 经代理执行单条 DoH 解析 (支持递归自动提取 CNAME 链与底层 A 记录)
     */
    public function resolve(string $domain, string $type = 'A', ?array $proxy = null): array
    {
        $startTime = microtime(true);
        $upstream = $proxy ? $this->dohUpstreams[array_rand($this->dohUpstreams)] : $this->dohUpstreams[mt_rand(0, 1)];
        $url = $upstream . '?name=' . urlencode($domain) . '&type=' . urlencode($type);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 4);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/dns-json',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) SRC-Monitor/1.2'
        ]);

        if ($proxy) {
            $this->applyProxyToCurl($ch, $proxy);
        }

        $response = curl_exec($ch);
        $err = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $duration = (int)((microtime(true) - $startTime) * 1000);

        if ($err || $httpCode !== 200 || empty($response)) {
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
        $answers = $this->parseDnsAnswers($json, $type);

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
     * 高性能并发批量 DoH 解析 (支持递归自动提取 CNAME 链与真实 A 记录)
     *
     * @param array $queries [['subdomain' => 'api.target.com', 'type' => 'A'], ...]
     * @param array|null $proxy
     * @return array ['api.target.com:A' => [...records...]]
     */
    public function resolveParallel(array $queries, ?array $proxy = null): array
    {
        if (empty($queries)) return [];

        $multi = curl_multi_init();
        $handles = [];
        $results = [];

        foreach ($queries as $idx => $q) {
            $sub = $q['subdomain'];
            $type = $q['type'] ?? 'A';
            $key = "{$sub}:{$type}";

            $upstream = $proxy ? $this->dohUpstreams[array_rand($this->dohUpstreams)] : $this->dohUpstreams[mt_rand(0, 1)];
            $url = $upstream . '?name=' . urlencode($sub) . '&type=' . urlencode($type);

            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 4);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Accept: application/dns-json',
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) SRC-Monitor/1.2'
            ]);

            if ($proxy) {
                $this->applyProxyToCurl($ch, $proxy);
            }

            curl_multi_add_handle($multi, $ch);
            $handles[$key] = $ch;
        }

        $active = null;
        $start = microtime(true);
        do {
            $mrc = curl_multi_exec($multi, $active);
            if ($active) {
                curl_multi_select($multi, 0.04);
            }
            if ((microtime(true) - $start) > 6.0) {
                break; // 超时保护
            }
        } while ($active && $mrc == CURLM_OK);

        foreach ($handles as $key => $ch) {
            $content = curl_multi_getcontent($ch);
            $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_multi_remove_handle($multi, $ch);
            curl_close($ch);

            $answers = [];
            if ($httpCode === 200 && !empty($content)) {
                $json = json_decode($content, true);
                $queryType = explode(':', $key)[1] ?? 'A';
                $answers = $this->parseDnsAnswers($json, $queryType);
            }
            $results[$key] = $answers;
        }

        curl_multi_close($multi);
        return $results;
    }

    /**
     * 智能识别并标准化 DNS Answer 中的各种记录类型 (Type 1=A, Type 5=CNAME, Type 28=AAAA, Type 16=TXT, Type 15=MX)
     */
    private function parseDnsAnswers(?array $json, string $fallbackType): array
    {
        $answers = [];
        if (!empty($json['Answer']) && is_array($json['Answer'])) {
            foreach ($json['Answer'] as $ans) {
                $rawType = $ans['type'] ?? 1;
                $mappedType = $fallbackType;

                if ($rawType == 1) {
                    $mappedType = 'A';
                } elseif ($rawType == 5) {
                    $mappedType = 'CNAME';
                } elseif ($rawType == 28) {
                    $mappedType = 'AAAA';
                } elseif ($rawType == 16) {
                    $mappedType = 'TXT';
                } elseif ($rawType == 15) {
                    $mappedType = 'MX';
                }

                $answers[] = [
                    'name' => rtrim($ans['name'] ?? '', '.'),
                    'type' => $mappedType,
                    'data' => trim($ans['data'] ?? '', '"'),
                    'ttl'  => $ans['TTL'] ?? 300
                ];
            }
        }
        return $answers;
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
