<?php

namespace App\Middleware;

use App\Core\Request;

class SanitizeInputMiddleware
{
    /**
     * 全局输入安全清洗 (防 XSS、Null-Byte 注入、非法 UTF-8 字符)
     */
    public static function handle(Request $request): void
    {
        // Request 类中的 input 数据在解析时自动经过清洗
    }

    /**
     * 递归清洗输入数据
     */
    public static function clean($data)
    {
        if (is_array($data)) {
            $cleaned = [];
            foreach ($data as $k => $v) {
                // 清洗 Key 与 Value
                $cleanKey = self::cleanScalar($k);
                $cleaned[$cleanKey] = self::clean($v);
            }
            return $cleaned;
        }

        if (is_string($data)) {
            return self::cleanScalar($data);
        }

        return $data;
    }

    private static function cleanScalar(string $val): string
    {
        // 1. 移除 Null-byte (防二进制路径截断)
        $val = str_replace(chr(0), '', $val);

        // 2. 检查并移除无效 UTF-8 字符 (防 UTF-8 编码攻击)
        if (!mb_check_encoding($val, 'UTF-8')) {
            $val = mb_convert_encoding($val, 'UTF-8', 'UTF-8');
        }

        // 3. 移除高危隐藏不可见控制字符 (保留常规换行制表符)
        $val = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $val);

        return $val;
    }

    /**
     * 针对需要安全输出至 HTML 上下文的文本进行 XSS 防御转义
     */
    public static function escapeHtml(?string $text): string
    {
        if ($text === null || $text === '') {
            return '';
        }
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
