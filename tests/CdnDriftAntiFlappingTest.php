<?php

require_once __DIR__ . '/../app/Services/Scanner/CdnDriftFilter.php';

use App\Services\Scanner\CdnDriftFilter;

echo "=== 启动 CDN Anycast 漂移与防抖抑制单元测试 ===\n";

// 1. 测试 Cloudflare Anycast IP 判定
$cfIp1 = '172.66.44.100';
$cfIp2 = '172.66.47.156';
$cfIp3 = '104.21.32.115';
$normalIp = '43.133.237.180';

assert(CdnDriftFilter::isCloudflareIp($cfIp1), "172.66.44.100 应被正确识别为 Cloudflare IP");
assert(CdnDriftFilter::isCloudflareIp($cfIp2), "172.66.47.156 应被正确识别为 Cloudflare IP");
assert(CdnDriftFilter::isCloudflareIp($cfIp3), "104.21.32.115 应被正确识别为 Cloudflare IP");
assert(!CdnDriftFilter::isCloudflareIp($normalIp), "43.133.237.180 绝非 Cloudflare IP");
echo "✅ 测试 1: Cloudflare 官方网段 CIDR 识别 100% 准确\n";

// 2. 测试 Cloudflare 内部 Anycast 漂移判定 (良性漂移，不应报警)
$isDrift = CdnDriftFilter::isBenignCdnDrift($cfIp1, $cfIp2);
assert($isDrift === true, "同在 Cloudflare 网段内的 IP 漂移应判定为良性 Anycast 调度");

$isDrift2 = CdnDriftFilter::isBenignCdnDrift($cfIp1, $cfIp3);
assert($isDrift2 === true, "不同 Cloudflare 子网间的 Anycast 轮换应判定为良性调度");
echo "✅ 测试 2: Cloudflare Anycast 漂移抑制算法生效\n";

// 3. 测试源站真实变更 (从 Cloudflare 切到自建独立 VPS，必须报警)
$realChange = CdnDriftFilter::isBenignCdnDrift($cfIp1, $normalIp);
assert($realChange === false, "从 CDN IP 切回真实服务器 IP 必须判定为真实变更并报警");
echo "✅ 测试 3: 真实源站解析变更精准放行告警\n";

// 4. 测试 EdgeOne / CNAME 链特征抑制
$edgeOneCname = json_encode(['api.2016xlx.cn.eo.dnse2.com']);
$edgeOneDrift = CdnDriftFilter::isBenignCdnDrift('36.35.39.162', '211.93.211.158', $edgeOneCname);
assert($edgeOneDrift === true, "包含 EdgeOne CNAME 链时其国内 Anycast IP 漂移应平滑抑制");
echo "✅ 测试 4: 腾讯云 EdgeOne 链式 Anycast 平滑抑制生效\n";

echo "🎉 全部 CDN 漂移与防误报单元测试 100% 通过！\n";
