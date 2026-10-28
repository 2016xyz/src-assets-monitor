<?php

namespace App\Core;

use App\Middleware\SanitizeInputMiddleware;

class Request
{
    private string $method;
    private string $uri;
    private array $headers = [];
    private array $query = [];
    private array $body = [];
    private string $rawBody = '';
    private string $ip;

    public function __construct()
    {
        $this->method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $parts = explode('?', $uri, 2);
        $this->uri = '/' . trim($parts[0], '/');
        
        // 全局输入清洗 (防 XSS、Null-byte 注入)
        $this->query = SanitizeInputMiddleware::clean($_GET);
        $this->rawBody = file_get_contents('php://input') ?: '';

        // Headers
        foreach ($_SERVER as $key => $val) {
            if (str_starts_with($key, 'HTTP_')) {
                $name = str_replace('_', '-', strtolower(substr($key, 5)));
                $this->headers[$name] = SanitizeInputMiddleware::clean($val);
            }
        }
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $this->headers['content-type'] = SanitizeInputMiddleware::clean($_SERVER['CONTENT_TYPE']);
        }

        // 解析 JSON
        if (str_contains($this->header('content-type', ''), 'application/json')) {
            $json = json_decode($this->rawBody, true);
            $parsedBody = is_array($json) ? $json : [];
            $this->body = SanitizeInputMiddleware::clean($parsedBody);
        } else {
            $this->body = SanitizeInputMiddleware::clean($_POST);
        }

        // IP 洗净防伪造与注入
        $rawIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        if (str_contains($rawIp, ',')) {
            $rawIp = trim(explode(',', $rawIp)[0]);
        }
        $filteredIp = filter_var($rawIp, FILTER_VALIDATE_IP);
        $this->ip = $filteredIp ?: '127.0.0.1';
    }

    public function method(): string
    {
        return $this->method;
    }

    public function uri(): string
    {
        return $this->uri;
    }

    public function ip(): string
    {
        return $this->ip;
    }

    public function header(string $key, $default = null): ?string
    {
        $key = strtolower($key);
        return $this->headers[$key] ?? $default;
    }

    public function query(string $key = null, $default = null)
    {
        if ($key === null) return $this->query;
        return $this->query[$key] ?? $default;
    }

    public function input(string $key = null, $default = null)
    {
        if ($key === null) return array_merge($this->query, $this->body);
        return $this->body[$key] ?? $this->query[$key] ?? $default;
    }

    public function all(): array
    {
        return array_merge($this->query, $this->body);
    }

    public function raw(): string
    {
        return $this->rawBody;
    }
}
