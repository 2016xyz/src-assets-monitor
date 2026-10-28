<?php

namespace App\Core;

class Cache
{
    private static $redis = null;

    private static function getRedis()
    {
        if (self::$redis === null && extension_loaded('redis')) {
            try {
                $r = new \Redis();
                $host = App::env('REDIS_HOST', '127.0.0.1');
                $port = (int)App::env('REDIS_PORT', 6379);
                $pass = App::env('REDIS_PASSWORD');
                if ($r->connect($host, $port, 2.0)) {
                    if ($pass) {
                        $r->auth($pass);
                    }
                    self::$redis = $r;
                }
            } catch (\Throwable $e) {
                self::$redis = false;
            }
        }
        return self::$redis ?: null;
    }

    public static function set(string $key, $value, int $ttl = 300): bool
    {
        $redis = self::getRedis();
        if ($redis) {
            return $redis->setex($key, $ttl, serialize($value));
        }

        $file = App::runtimePath('cache_' . md5($key) . '.data');
        $payload = [
            'expire' => time() + $ttl,
            'data'   => $value
        ];
        return file_put_contents($file, serialize($payload)) !== false;
    }

    public static function get(string $key, $default = null)
    {
        $redis = self::getRedis();
        if ($redis) {
            $val = $redis->get($key);
            return $val !== false ? unserialize($val) : $default;
        }

        $file = App::runtimePath('cache_' . md5($key) . '.data');
        if (!file_exists($file)) return $default;
        $content = file_get_contents($file);
        if (!$content) return $default;

        $payload = @unserialize($content);
        if (!$payload || !isset($payload['expire'])) return $default;

        if (time() > $payload['expire']) {
            @unlink($file);
            return $default;
        }
        return $payload['data'];
    }

    public static function delete(string $key): bool
    {
        $redis = self::getRedis();
        if ($redis) {
            return $redis->del($key) > 0;
        }
        $file = App::runtimePath('cache_' . md5($key) . '.data');
        if (file_exists($file)) {
            return @unlink($file);
        }
        return true;
    }
}
