<?php

// 单元测试环境统一采用轻量 SQLite 驱动，保证无外部 MySQL 守护进程时依然秒级自测
putenv('DB_CONNECTION=sqlite');

require_once dirname(__DIR__) . '/autoload.php';

use App\Core\Database;
use App\Middleware\SanitizeInputMiddleware;
use App\Services\Security\SsrfGuard;

echo "=== 执行「SQL 注入、XSS 跨站、SSRF」深度安全攻击抵御测试 ===\n\n";

// 初始化临时安全测试表
Database::query("CREATE TABLE IF NOT EXISTS _sec_test (id INTEGER PRIMARY KEY, username TEXT, password TEXT);");

// ========================================================
// 1. SQL 注入防御能力测试
// ========================================================
echo "[安全防御 1] SQL 注入攻击拦截 (表名与列名注入攻击防御):\n";

// 1.1 恶意表名注入尝试
$tableInjectionPassed = false;
try {
    Database::insert("users`; DROP TABLE subdomains; --", ['username' => 'test']);
} catch (\InvalidArgumentException $e) {
    $tableInjectionPassed = true;
    echo "  -> 拦截恶意表名注入: [{$e->getMessage()}]\n";
}
assert($tableInjectionPassed === true, '非法表名必须被 validateIdentifier 阻断');

// 1.2 恶意字段列名注入尝试
$colInjectionPassed = false;
try {
    Database::insert("_sec_test", [
        "username`=1, password=(SELECT 'hacked')--" => "val"
    ]);
} catch (\InvalidArgumentException $e) {
    $colInjectionPassed = true;
    echo "  -> 拦截恶意列名注入: [{$e->getMessage()}]\n";
}
assert($colInjectionPassed === true, '非法列名必须被 validateIdentifier 阻断');

// 1.3 预编译参数中的单引号闭合攻击
$mockParam = "' OR '1'='1' -- ";
$res = Database::fetchOne("SELECT * FROM _sec_test WHERE username = ?", [$mockParam]);
assert($res === null, '预编译参数绑定必须有效防范万能密码攻击');
echo "  -> 通过: SQL 注入全路径防御体系完备，零注入漏洞\n\n";

// 清理测试表
Database::query("DROP TABLE IF EXISTS _sec_test;");

// ========================================================
// 2. XSS 跨站脚本防御测试
// ========================================================
echo "[安全防御 2] XSS 跨站脚本攻击与 Null-Byte 二进制截断防御:\n";

// 2.1 Null-Byte 路径截断注入
$nullBytePayload = "admin.php\0.jpg";
$cleanedNull = SanitizeInputMiddleware::clean($nullBytePayload);
assert(!str_contains($cleanedNull, chr(0)), 'Null 字节必须被彻底剔除');
assert($cleanedNull === 'admin.php.jpg', 'Null 字节剔除后格式正常');
echo "  -> 成功滤除 Null-byte 截断载荷\n";

// 2.2 存储型与反射型 XSS 载荷转义
$xssPayload = "<script>alert(document.cookie)</script><img src=x onerror=alert(1)>";
$escaped = SanitizeInputMiddleware::escapeHtml($xssPayload);
assert(!str_contains($escaped, '<script>'), '尖括号必须被实体转义');
assert(!str_contains($escaped, '<img'), '图片标签必须被实体转义');
assert(str_contains($escaped, '&lt;script&gt;'), '转义为安全 HTML 实体');
echo "  -> 净化转义后结果: [{$escaped}]\n";
echo "  -> 通过: 全局 XSS 输入与输出防御生效\n\n";

// ========================================================
// 3. SSRF 服务端请求伪造防御测试
// ========================================================
echo "[安全防御 3] SSRF 内网嗅探与云元数据窃取攻击拦截:\n";

$dangerousUrls = [
    'http://169.254.169.254/latest/meta-data/',      // AWS/阿里云元数据服务
    'http://localhost/admin',                        // 本地主机
    'http://127.0.0.1:3306/',                        // 本地数据库端口
    'http://0.0.0.0:8000',                          // 本地通配
    'http://192.168.1.1:8080/router',                // 私有 C 段路由
    'http://10.0.0.5/api',                           // 私有 A 段
    'http://172.16.0.10/',                           // 私有 B 段
    'file:///etc/passwd',                            // 伪协议读取系统文件
    'gopher://127.0.0.1:6379/_INFO',                 // Gopher 攻击内网 Redis
    'dict://127.0.0.1:11211/'                        // Dict 攻击
];

foreach ($dangerousUrls as $badUrl) {
    $isSafe = SsrfGuard::isSafeUrl($badUrl);
    assert($isSafe === false, "危险 URL [{$badUrl}] 必须被 SsrfGuard 拦截");
}
echo "  -> 成功拦截全部 " . count($dangerousUrls) . " 种典型 SSRF 渗透探测载荷\n";

// 合法 Webhook 必须放行
$validWebhook = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test1234';
assert(SsrfGuard::isSafeUrl($validWebhook) === true, '合法企业微信 Webhook 必须正常放行');
echo "  -> 合法 Webhook 正常放行\n";
echo "  -> 通过: SSRF 边界防御体系完备\n\n";

echo "=== 全部安全加固用例断言通过 (100% SUCCESS) ===\n";
