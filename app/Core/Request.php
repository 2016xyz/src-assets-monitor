<?php

namespace App\Core;

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
        $this->query = $_GET;
        $this->rawBody = file_get_contents('php://input') ?: '';

        // Headers
        foreach ($_SERVER as $key => $val) {
            if (str_starts_with($key, 'HTTP_')) {
                $name = str_replace('_', '-', strtolower(substr($key, 5)));
                $this->headers[$name] = $val;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $this->headers['content-type'] = $_SERVER['CONTENT_TYPE'];
        }

        // 解析 JSON
        if (str_contains($this->header('content-type', ''), 'application/json')) {
            $json = json_decode($this->rawBody, true);
            $this->body = is_array($json) ? $json : [];
        } else {
            $this->body = $_POST;
        }

        $this->ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        if (str_contains($this->ip, ',')) {
            $this->ip = trim(explode(',', $this->ip)[0]);
        }
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
