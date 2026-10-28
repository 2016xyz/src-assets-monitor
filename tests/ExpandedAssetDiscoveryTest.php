<?php

require_once dirname(__DIR__) . '/autoload.php';

use App\Services\Scanner\BucketTakeoverDetector;
use App\Services\Scanner\CnameAnalyzer;
use App\Services\Scanner\GitHubDorkScanner;
use App\Services\Scanner\JsSourceMapExtractor;
use App\Services\Scanner\PassiveCollectorPool;
use App\Services\Scanner\ResolverPool;
use App\Services\Scanner\WildcardDetector;
use App\Services\Proxy\DoHProxyClient;
use App\Services\Proxy\CircuitBreaker;

echo "=== 开始「扩展多方法检测新资产」自动化全项测试 ===\n\n";

// 1. 测试多源被动收集结果归一化与去重 (小写/去通配符/去尾部点/去外部域)
echo "[测试 1] 被动收集结果归一化与去重规则:\n";
$passivePool = new PassiveCollectorPool();
$rawInputs = [
    '*.api.target.com',
    'API.TARGET.COM.',
    'mail.target.com',
    'evil.attacker.org', // 外部域应剔除
    'target.com',        // 根主域应剔除
    'oa.target.com/index.php', // 非法主机名
    '*.vpn.target.com'
];
$cleaned = $passivePool->normalizeSubdomains($rawInputs, 'target.com');
echo "  -> 归一化清洗后结果: " . json_encode($cleaned) . "\n";
assert(in_array('api.target.com', $cleaned, true), '必须包含 api.target.com');
assert(in_array('mail.target.com', $cleaned, true), '必须包含 mail.target.com');
assert(in_array('vpn.target.com', $cleaned, true), '通配符 *. 前缀必须剥离');
assert(!in_array('evil.attacker.org', $cleaned, true), '外部域必须剔除');
assert(!in_array('target.com', $cleaned, true), '主域名自身必须剔除');
echo "  -> 通过: 被动数据源归一化去重完全正确\n\n";

// 2. 测试开放解析器池管理类
echo "[测试 2] 开放解析器池轮询与限速:\n";
$resolverPool = new ResolverPool();
$r1 = $resolverPool->getNextResolver();
$r2 = $resolverPool->getNextResolver();
echo "  -> 轮询获取解析器: [{$r1}], [{$r2}]\n";
assert(filter_var($r1, FILTER_VALIDATE_IP), '解析器必须是有效 IP');
assert(filter_var($r2, FILTER_VALIDATE_IP), '解析器必须是有效 IP');
echo "  -> 通过: 开放解析器池管理就绪\n\n";

// 3. 测试泛解析检测与过滤逻辑
echo "[测试 3] 泛解析检测与特征池过滤:\n";
$cb = new CircuitBreaker();
$doh = new DoHProxyClient($cb);
$wildcardDetector = new WildcardDetector($doh);

$mockWildcardData = [
    'has_wildcard'    => true,
    'wildcard_ips'    => ['120.55.22.88', '120.55.22.89'],
    'wildcard_cnames' => ['wildcard.cdn.example.com']
];
assert($wildcardDetector->isWildcardMatch('120.55.22.88', $mockWildcardData) === true, '命中泛解析IP应被过滤');
assert($wildcardDetector->isWildcardMatch('wildcard.cdn.example.com', $mockWildcardData) === true, '命中泛解析CNAME应被过滤');
assert($wildcardDetector->isWildcardMatch('1.2.3.4', $mockWildcardData) === false, '未命中泛解析应正常放行');
echo "  -> 通过: 泛解析匹配逻辑判定精准\n\n";

// 4. 测试 CNAME 链追踪与悬挂/第三方托管平台标记
echo "[测试 4] CNAME 链分析与第三方托管识别:\n";
$cnameAnalyzer = new CnameAnalyzer($doh);
$reflector = new ReflectionClass(CnameAnalyzer::class);
$prop = $reflector->getProperty('thirdPartyProviders');
$prop->setAccessible(true);
$providers = $prop->getValue($cnameAnalyzer);

assert(isset($providers['github.io']) && $providers['github.io'] === 'GitHub Pages', '需覆盖 GitHub Pages');
assert(isset($providers['s3.amazonaws.com']) && $providers['s3.amazonaws.com'] === 'AWS S3 Bucket', '需覆盖 AWS S3');
assert(isset($providers['vercel.app']) && $providers['vercel.app'] === 'Vercel', '需覆盖 Vercel');
echo "  -> 通过: 涵盖 " . count($providers) . " 种主流第三方云平台接管指纹\n\n";

// 5. 测试云存储桶只读存在性检查候选生成
echo "[测试 5] 云存储桶候选名称枚举 (严格只读):\n";
$bucketDetector = new BucketTakeoverDetector();
$candidates = $bucketDetector->generateBucketCandidates('target.com');
echo "  -> 自动生成候选桶: " . json_encode(array_slice($candidates, 0, 5)) . "...\n";
assert(in_array('target-backup', $candidates, true), '应包含 target-backup');
assert(in_array('target-dev', $candidates, true), '应包含 target-dev');
assert(in_array('target-assets', $candidates, true), '应包含 target-assets');
echo "  -> 通过: 云存储只读候选生成就绪\n\n";

// 6. 测试 GitHub Dorks 代码泄露文本提取与域名校验
echo "[测试 6] GitHub Dorks 代码片段正则提取与 FQDN 合法性校验:\n";
$githubScanner = new GitHubDorkScanner();
$snippet = "
const API_URL = 'https://api-internal.target.com/v1/auth';
const STAGING = 'https://stg-portal.target.com:8443';
const INVALID = 'http://not-target.org';
const BAD = '...target.com';
";
$extracted = $githubScanner->extractValidDomains($snippet, 'target.com');
echo "  -> 代码片段提取结果: " . json_encode($extracted) . "\n";
assert(in_array('api-internal.target.com', $extracted, true), '必须提取出 api-internal.target.com');
assert(in_array('stg-portal.target.com', $extracted, true), '必须提取出 stg-portal.target.com');
assert(!in_array('not-target.org', $extracted, true), '非目标主域必须过滤');
assert(!in_array('...target.com', $extracted, true), '非法格式必须过滤');
echo "  -> 通过: 代码泄露资产搜寻与域名校验精准\n\n";

// 7. 测试 JavaScript 与 Source Map 文本挖掘
echo "[测试 7] JavaScript 脚本与 Source Map 资产挖掘正则:\n";
$jsExtractor = new JsSourceMapExtractor();
$jsReflector = new ReflectionClass(JsSourceMapExtractor::class);
$matchMethod = $jsReflector->getMethod('matchDomainsInText');
$matchMethod->setAccessible(true);

$jsCode = "
var endpoint = 'https://gateway-ops.target.com/graphql';
var ws = 'wss://push-stream.target.com/socket';
";
$jsSubs = $matchMethod->invoke($jsExtractor, $jsCode, 'target.com');
echo "  -> JS 代码提取结果: " . json_encode($jsSubs) . "\n";
assert(in_array('gateway-ops.target.com', $jsSubs, true), '必须提取出 gateway-ops.target.com');
assert(in_array('push-stream.target.com', $jsSubs, true), '必须提取出 push-stream.target.com');
echo "  -> 通过: JS 与 Source Map 挖掘器校验通过\n\n";

echo "=== 全部 7 大类核心扩展用例断言通过 (100% SUCCESS) ===\n";
