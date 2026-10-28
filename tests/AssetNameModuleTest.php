<?php

require_once dirname(__DIR__) . '/autoload.php';

use App\Core\Database;
use App\Services\Notifier\NotificationManager;
use App\Services\Proxy\CircuitBreaker;
use App\Services\Proxy\ProxyRateLimiter;
use App\Services\Proxy\ProxyScheduler;
use App\Services\Scanner\AssetNameResolver;

echo "=== 开始「资产名称记录 + 通知显示名称」自动化测试 ===\n\n";

$resolver = new AssetNameResolver();

// 1. 测试 Alias 别名最高优先级
echo "[测试 1] 别名优先级最高:\n";
$res1 = $resolver->resolve('oa.target.com', 'target.com', 'A', '1.1.1.1', '办公统一门户OA');
assert($res1['asset_name'] === '办公统一门户OA', '别名应被优先使用');
assert($res1['asset_name_source'] === 'alias', '来源应为 alias');
echo "  -> 通过: 资产名称={$res1['asset_name']}, 来源={$res1['asset_name_source']}\n\n";

// 2. 测试 CNAME 来源识别
echo "[测试 2] CNAME 记录回退识别:\n";
$res2 = $resolver->resolve('static.target.com', 'target.com', 'CNAME', 'westeurope.cdn.cloudflare.net', null);
assert($res2['asset_name'] === 'westeurope.cdn.cloudflare.net', 'CNAME目标应作为资产名称');
assert($res2['asset_name_source'] === 'cname', '来源应为 cname');
echo "  -> 通过: 资产名称={$res2['asset_name']}, 来源={$res2['asset_name_source']}\n\n";

// 3. 测试 标题安全清洗与防 XSS 截断机制 (反射测试私有 extractTitle 方法)
echo "[测试 3] 标题清洗 (去空白/实体解码/HTML转义/超120字截断):\n";
$reflector = new ReflectionClass(AssetNameResolver::class);
$extractTitleMethod = $reflector->getMethod('extractTitle');
$extractTitleMethod->setAccessible(true);

// XSS 尝试与 HTML 实体
$dirtyHtml = "<html><head><title>  &lt;script&gt;alert(1)&lt;/script&gt;  SRC  测试系统   </title></head></html>";
$cleanTitle = $extractTitleMethod->invoke($resolver, $dirtyHtml);
echo "  -> 清洗后结果: [{$cleanTitle}]\n";
assert(str_contains($cleanTitle, '&lt;script&gt;'), 'HTML标签字符必须转义存储防XSS');
assert(!str_contains($cleanTitle, '   '), '多余空白必须被压缩');

// 超长 150 字截断
$longTitle = str_repeat('超长资产名称', 20);
$longHtml = "<html><head><title>{$longTitle}</title></head></html>";
$truncated = $extractTitleMethod->invoke($resolver, $longHtml);
assert(mb_strlen($truncated, 'UTF-8') <= 120, '长度必须限制在120字以内');
assert(str_ends_with($truncated, '…'), '截断末尾必须追加省略号');
echo "  -> 截断后长度: " . mb_strlen($truncated, 'UTF-8') . " 字符\n";
echo "  -> 通过: 标题防 XSS 与截断均生效\n\n";

// 4. 测试 邮件通知模板渲染与回退规则
echo "[测试 4] 邮件通知模板与回退规则:\n";
$cb = new CircuitBreaker();
$rl = new ProxyRateLimiter();
$scheduler = new ProxyScheduler($cb, $rl);
$notifierMgr = new NotificationManager($scheduler);

// 单条变动 (有识别标题)
$email1 = $notifierMgr->formatEmailBody('target.com', [
    [
        'subdomain'         => 'vpn.target.com',
        'asset_name'        => '全球SSL安全接入网关',
        'asset_name_source' => 'http_title',
        'change_type'       => 'added',
        'new_value'         => '120.25.14.88 (A)'
    ]
]);
echo "--- 邮件输出样本 1 (正常标题) ---\n" . $email1 . "\n----------------\n";
assert(str_contains($email1, '全球SSL安全接入网关'), '邮件中必须包含资产名称');
assert(str_contains($email1, '网页标题'), '来源必须中文化为 网页标题');

// 单条变动 (未识别，触发 (名称未识别) 回退)
$email2 = $notifierMgr->formatEmailBody('target.com', [
    [
        'subdomain'         => 'unknown.target.com',
        'asset_name'        => 'unknown.target.com', // 与子域名相同
        'asset_name_source' => 'hostname',
        'change_type'       => 'added',
        'new_value'         => '10.0.0.1'
    ]
]);
echo "--- 邮件输出样本 2 (未识别回退) ---\n" . $email2 . "\n----------------\n";
assert(str_contains($email2, 'unknown.target.com (名称未识别)'), '回退时必须追加 (名称未识别)');
assert(str_contains($email2, '未识别'), '来源中文化为 未识别');

// 5. 测试 企微/钉钉/飞书 Markdown 聚合格式
echo "[测试 5] 多条变动聚合通知格式 (• {{asset_name}}（{{subdomain}}）— {{change_type}}):\n";
$mdAgg = $notifierMgr->formatMarkdown('target.com', [
    [
        'subdomain'         => 'oa.target.com',
        'asset_name'        => '办公协同平台',
        'asset_name_source' => 'http_title',
        'change_type'       => 'added'
    ],
    [
        'subdomain'         => 'dev.target.com',
        'asset_name'        => 'dev.target.com',
        'asset_name_source' => 'hostname',
        'change_type'       => 'changed'
    ]
]);
echo "--- Markdown 聚合推送输出 ---\n" . $mdAgg . "\n----------------\n";
assert(str_contains($mdAgg, '• **办公协同平台**（`oa.target.com`）— 🆕 新增解析'), '聚合单行格式必须正确');
assert(str_contains($mdAgg, '• **dev.target.com (名称未识别)**（`dev.target.com`）— 🔄 解析变更'), '聚合未识别回退必须正确');

echo "\n=== 全部测试用例断言通过 (100% SUCCESS) ===\n";
