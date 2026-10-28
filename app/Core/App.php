<?php

namespace App\Core;

class App
{
    private static ?App $instance = null;
    private array $bindings = [];

    public static function getInstance(): App
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public static function basePath(string $path = ''): string
    {
        return dirname(__DIR__, 2) . ($path ? DIRECTORY_SEPARATOR . ltrim($path, '/\\') : '');
    }

    public static function runtimePath(string $path = ''): string
    {
        $dir = self::basePath('runtime');
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        return $dir . ($path ? DIRECTORY_SEPARATOR . ltrim($path, '/\\') : '');
    }

    public static function publicPath(string $path = ''): string
    {
        return self::basePath('public' . ($path ? DIRECTORY_SEPARATOR . ltrim($path, '/\\') : ''));
    }

    public static function env(string $key, $default = null)
    {
        static $envVars = null;
        if ($envVars === null) {
            $envVars = [];
            $envFile = self::basePath('.env');
            if (file_exists($envFile)) {
                $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line === '' || str_starts_with($line, '#')) {
                        continue;
                    }
                    if (str_contains($line, '=')) {
                        [$k, $v] = explode('=', $line, 2);
                        $k = trim($k);
                        $v = trim($v, " \t\n\r\0\x0B\"'");
                        $envVars[$k] = $v;
                    }
                }
            }
        }
        return $envVars[$key] ?? getenv($key) ?: $default;
    }
}
