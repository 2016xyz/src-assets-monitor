<?php

namespace App\Services\Proxy;

use App\Core\Crypto;
use App\Core\Database;

class ProxyHealthChecker
{
    private CircuitBreaker $circuitBreaker;

    public function __construct(CircuitBreaker $cb)
    {
        $this->circuitBreaker = $cb;
    }

    public function check(array $proxy): array
    {
        $start = microtime(true);
        $ch = curl_init('https://api.ipify.org?format=json');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 6);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 4);

        $proto = strtolower($proxy['protocol'] ?? 'http');
        $proxyType = match ($proto) {
            'https'   => CURLPROXY_HTTPS,
            'socks5'  => CURLPROXY_SOCKS5,
            'socks5h' => CURLPROXY_SOCKS5_HOSTNAME,
            default   => CURLPROXY_HTTP
        };

        curl_setopt($ch, CURLOPT_PROXYTYPE, $proxyType);
        curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");

        if (!empty($proxy['auth_user'])) {
            $pass = !empty($proxy['auth_pass_encrypted']) ? Crypto::decrypt($proxy['auth_pass_encrypted']) : '';
            curl_setopt($ch, CURLOPT_PROXYUSERPWD, "{$proxy['auth_user']}:{$pass}");
        }

        $res = curl_exec($ch);
        $err = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $latency = (int)((microtime(true) - $start) * 1000);

        if (!$err && $httpCode === 200) {
            $json = json_decode($res, true);
            $ip = $json['ip'] ?? null;
            $this->circuitBreaker->recordSuccess($proxy['id'], $latency, $ip);
            Database::insert('proxy_health_logs', [
                'proxy_id'      => $proxy['id'],
                'status'        => 'healthy',
                'latency_ms'    => $latency,
                'egress_ip'     => $ip,
                'error_code'    => null,
                'error_message' => '探针正常',
                'created_at'    => date('Y-m-d H:i:s')
            ]);
            return ['healthy' => true, 'latency_ms' => $latency, 'egress_ip' => $ip];
        }

        $msg = $err ?: "HTTP {$httpCode}";
        $this->circuitBreaker->recordFailure($proxy['id'], $msg);
        Database::insert('proxy_health_logs', [
            'proxy_id'      => $proxy['id'],
            'status'        => 'unhealthy',
            'latency_ms'    => $latency,
            'egress_ip'     => null,
            'error_code'    => 'ERR_PROBE',
            'error_message' => substr($msg, 0, 250),
            'created_at'    => date('Y-m-d H:i:s')
        ]);
        return ['healthy' => false, 'latency_ms' => $latency, 'error' => $msg];
    }
}
