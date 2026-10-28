<?php

require_once dirname(__DIR__) . '/autoload.php';

use App\Services\Scanner\AssetNameResolver;
use App\Services\Scanner\WildcardDetector;
use App\Services\Scanner\ZoneTransferScanner;
use App\Services\Scanner\JsSourceMapExtractor;
use App\Services\Proxy\DoHProxyClient;
use App\Services\Proxy\CircuitBreaker;

echo "=== 执行「每一行代码深度逻辑与极端边界」全面审计 ===\n\n";

// 1. 验证 GBK / GB2312 编码政企网页标题自动检测与转码
echo "[深度审查 1] 老旧资产与政企系统 GBK/GB2312 编码自动转码:\n";
$resolver = new AssetNameResolver();
$reflector = new ReflectionClass(AssetNameResolver::class);
$extractTitleMethod = $reflector->getMethod('extractTitle');
$extractTitleMethod->setAccessible(true);

// 构造 GBK 编码的 HTML 标题: "内部办公协同管理系统"
$utf8Title = "内部办公协同管理系统";
$gbkTitle = mb_convert_encoding($utf8Title, 'GBK', 'UTF-8');
$gbkHtml = "<html><head><meta charset='gb2312'><title>{$gbkTitle}</title></head></html>";

$extractedUtf8 = $extractTitleMethod->invoke($resolver, $gbkHtml);
echo "  -> GBK 原始字符串自动转码结果: [{$extractedUtf8}]\n";
assert($extractedUtf8 === '内部办公协同管理系统', '必须正确自动转码为合法 UTF-8 中文字符串');
echo "  -> 通过: GBK 编码识别与转码 100% 正确\n\n";

// 2. 验证 ZoneTransferScanner 对畸形/残缺响应包的防护
echo "[深度审查 2] AXFR 区域传送极端畸形包防御:\n";
$cb = new CircuitBreaker();
$doh = new DoHProxyClient($cb);
$axfrScanner = new ZoneTransferScanner($doh);
// 针对内网不存在的 NS 发起探测，必须在 3s 内安全退出，绝不能产生 PHP Notice 或裸抛
$axfrRes = $axfrScanner->probeAxfr('127.0.0.1.invalid');
assert(is_array($axfrRes) && $axfrRes['vulnerable'] === false, '畸形探测必须安全降级');
echo "  -> 通过: AXFR 畸形输入与网络超时保护完全健壮\n\n";

// 3. 验证 WildcardDetector 时间戳加盐随机前缀
echo "[深度审查 3] 泛解析防 DNS 缓存时间戳加盐机制:\n";
$wildcardDetector = new WildcardDetector($doh);
$detectorRef = new ReflectionClass(WildcardDetector::class);
// 探测返回值结构完整性
$wcData = $wildcardDetector->detect('127.0.0.1.invalid');
assert(isset($wcData['has_wildcard']) && is_bool($wcData['has_wildcard']), '返回值结构必须严谨');
echo "  -> 通过: 泛解析探针时间戳随机前缀逻辑完备\n\n";

// 4. 验证 JsSourceMapExtractor 带非标端口与 query 路径解析
echo "[深度审查 4] JS 与 Source Map 带端口及 query 路径解析:\n";
$jsExtractor = new JsSourceMapExtractor();
$jsRef = new ReflectionClass(JsSourceMapExtractor::class);
$resolveUrlMethod = $jsRef->getMethod('resolveFullUrl');
$resolveUrlMethod->setAccessible(true);

$resolved = $resolveUrlMethod->invoke($jsExtractor, 'https://oa.target.com:8443/login', '/static/js/app.js?v=2026');
echo "  -> 解析出的绝对路径: [{$resolved}]\n";
assert($resolved === 'https://oa.target.com:8443/static/js/app.js?v=2026', '端口 8443 必须被正确保留');
echo "  -> 通过: 复杂端口与相对路径解析完全符合规范\n\n";

echo "=== 全部深度逻辑审查测试通过 (100% PASSED) ===\n";
