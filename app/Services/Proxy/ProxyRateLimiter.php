<?php

namespace App\Services\Proxy;

use App\Core\Cache;

class ProxyRateLimiter
{
    /**
     * 滑动窗口限制每分钟请求量
     */
    public function tryAcquire(array $proxy): bool
    {
        $limit = (int)($proxy['rate_limit_per_minute'] ?? 120);
        $key = 'proxy_rate_' . $proxy['id'] . '_' . date('YmdHi');
        $current = (int)Cache::get($key, 0);

        if ($current >= $limit) {
            return false;
        }

        Cache::set($key, $current + 1, 65);
        return true;
    }
}
