<?php

require_once __DIR__ . '/../app/Core/Cache.php';
require_once __DIR__ . '/../app/Services/Scanner/CdnDriftFilter.php';
require_once __DIR__ . '/../app/Services/Scanner/IpGeoResolver.php';
require_once __DIR__ . '/../app/Services/Proxy/CircuitBreaker.php';
require_once __DIR__ . '/../app/Services/Proxy/DoHProxyClient.php';
require_once __DIR__ . '/../app/Services/Scanner/AssetDeepProbe.php';

use App\Services\Scanner\IpGeoResolver;
use App\Services\Scanner\AssetDeepProbe;

echo "=== 启动资产全景画像与 IP 归属地解析单元测试 ===\n";

// 1. 测试私有保留地址解析
$privGeo = IpGeoResolver::resolve('192.168.1.1');
assert($privGeo['country'] === '局域网', "私有 IP 应正确解析为局域网地址");
echo "✅ 测试 1: RFC1918 私有保留地址识别正确\n";

// 2. 测试 Cloudflare Anycast IP 快速解析 (毫秒级直出)
$cfGeo = IpGeoResolver::resolve('172.66.44.100');
assert($cfGeo['is_cdn'] === true, "Cloudflare Anycast IP 必须被识别为 CDN");
assert(str_contains($cfGeo['isp'], 'Cloudflare'), "Cloudflare ASN 识别正确");
echo "✅ 测试 2: Cloudflare Anycast CDN 归属地直出生效\n";

// 3. 测试 AssetDeepProbe 初始化与方法健全性
$probe = new AssetDeepProbe();
assert(method_exists($probe, 'inspect'), "AssetDeepProbe 必须包含 inspect 方法");
echo "✅ 测试 3: AssetDeepProbe 全景画像探针组件就绪\n";

echo "🎉 全景画像与 Geo 单元测试全部通过！\n";
