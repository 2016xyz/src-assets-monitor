<?php

namespace App\Services\Proxy;

use App\Core\Database;

class CircuitBreaker
{
    public const MAX_FAILS = 3;
    public const COOLDOWN_SECONDS = 300;

    public function isAvailable(array $proxy): bool
    {
        if (empty($proxy['status'])) {
            return false;
        }

        if ($proxy['health_status'] === 'healthy') {
            return true;
        }

        if ($proxy['health_status'] === 'unhealthy') {
            $updatedAt = strtotime($proxy['updated_at'] ?? '2000-01-01');
            if (time() - $updatedAt >= self::COOLDOWN_SECONDS) {
                // 冷却期后转为半开探测状态
                Database::update('proxies', ['health_status' => 'semi-open'], 'id = ?', [$proxy['id']]);
                return true;
            }
            return false;
        }

        return true; // semi-open 允许试探
    }

    public function recordSuccess(int $proxyId, int $latencyMs, ?string $egressIp = null): void
    {
        $update = [
            'health_status'       => 'healthy',
            'consecutive_fails'   => 0,
            'last_error'          => null,
            'latency_ms'          => $latencyMs,
            'last_check_at'       => date('Y-m-d H:i:s'),
            'updated_at'          => date('Y-m-d H:i:s')
        ];
        if ($egressIp) {
            $update['egress_ip'] = $egressIp;
        }
        Database::update('proxies', $update, 'id = ?', [$proxyId]);
        Database::query("UPDATE proxies SET used_requests_today = used_requests_today + 1 WHERE id = ?", [$proxyId]);
    }

    public function recordFailure(int $proxyId, string $errorMsg): void
    {
        $proxy = Database::fetchOne("SELECT consecutive_fails, health_status FROM proxies WHERE id = ?", [$proxyId]);
        if (!$proxy) return;

        $fails = (int)$proxy['consecutive_fails'] + 1;
        $newHealth = $proxy['health_status'];
        if ($fails >= self::MAX_FAILS || $proxy['health_status'] === 'semi-open') {
            $newHealth = 'unhealthy';
        }

        Database::update('proxies', [
            'consecutive_fails' => $fails,
            'health_status'     => $newHealth,
            'last_error'        => substr($errorMsg, 0, 250),
            'last_check_at'     => date('Y-m-d H:i:s'),
            'updated_at'        => date('Y-m-d H:i:s')
        ], 'id = ?', [$proxyId]);
    }
}
