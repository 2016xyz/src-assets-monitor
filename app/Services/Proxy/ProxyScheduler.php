<?php

namespace App\Services\Proxy;

use App\Core\Cache;
use App\Core\Database;

class ProxyScheduler
{
    private CircuitBreaker $circuitBreaker;
    private ProxyRateLimiter $rateLimiter;

    public function __construct(CircuitBreaker $cb, ProxyRateLimiter $rl)
    {
        $this->circuitBreaker = $cb;
        $this->rateLimiter = $rl;
    }

    /**
     * 根据组策略调度最优节点
     */
    public function selectProxy(int $groupId, ?string $affinityKey = null): ?array
    {
        $group = Database::fetchOne("SELECT * FROM proxy_groups WHERE id = ?", [$groupId]);
        if (!$group) return null;

        $nodes = Database::fetchAll("
            SELECT p.* FROM proxies p
            INNER JOIN proxy_group_items pgi ON pgi.proxy_id = p.id
            WHERE pgi.group_id = ? AND p.status = 1
        ", [$groupId]);

        if (empty($nodes)) return null;

        // 过滤熔断中与限流中的节点
        $available = array_filter($nodes, function ($p) {
            return $this->circuitBreaker->isAvailable($p) && $this->rateLimiter->tryAcquire($p);
        });

        if (empty($available)) {
            return null;
        }

        $available = array_values($available);
        $strategy = $group['strategy'] ?? 'round-robin';

        switch ($strategy) {
            case 'sticky':
                if (!empty($affinityKey)) {
                    $idx = sprintf('%u', crc32($affinityKey)) % count($available);
                    return $available[$idx];
                }
                return $available[array_rand($available)];

            case 'weighted':
                $total = array_sum(array_column($available, 'priority'));
                if ($total <= 0) return $available[array_rand($available)];
                $rand = mt_rand(1, $total);
                $cur = 0;
                foreach ($available as $item) {
                    $cur += (int)$item['priority'];
                    if ($rand <= $cur) return $item;
                }
                return $available[0];

            case 'random':
                return $available[array_rand($available)];

            case 'round-robin':
            default:
                $key = 'rr_idx_' . $groupId;
                $idx = (int)Cache::get($key, 0);
                $selected = $available[$idx % count($available)];
                Cache::set($key, $idx + 1, 86400);
                return $selected;
        }
    }
}
