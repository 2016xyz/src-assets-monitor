<?php

namespace App\Core;

class Response
{
    public static function json($data = null, int $code = 0, string $msg = 'success', int $httpStatus = 200): void
    {
        http_response_code($httpStatus);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'code' => $code,
            'msg'  => $msg,
            'data' => $data
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    public static function error(string $msg = 'error', int $code = 500, int $httpStatus = 500, $data = null): void
    {
        self::json($data, $code, $msg, $httpStatus);
    }
}
