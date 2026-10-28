<?php

namespace App\Services\Scanner;

use App\Services\Proxy\DoHProxyClient;

class WildcardDetector
{
    private DoHProxyClient $dohClient;

    public function __construct(DoHProxyClient $doh)
    {
        $this->dohClient = $doh;
    }

    /**
     * 探测目标主域名是否存在泛解析 (Wildcard DNS)
     *
     * @param string $mainDomain 目标主域名 (如 target.com)
     * @param array|null $proxy 出口代理
     * @return array [
     *   'has_wildcard' => bool,
     *   'wildcard_ips' => ['1.2.3.4'],
     *   'wildcard_cnames' => ['wildcard.cdn.com'],
     *   'tested_count' => int
     * ]
     */
    public function detect(string $mainDomain, ?array $proxy = null): array
    {
        $wildcardIps = [];
        $wildcardCnames = [];

        // 生成 3 个强随机绝对不存在的子域名
        $randomPrefixes = [
            'rnd-' . bin2hex(random_bytes(6)),
            'nx-' . bin2hex(random_bytes(6)),
            'chk-' . bin2hex(random_bytes(6))
        ];

        $resolvedCount = 0;

        foreach ($randomPrefixes as $pfx) {
            $testSub = "{$pfx}.{$mainDomain}";
            $resA = $this->dohClient->resolve($testSub, 'A', $proxy);
            $resCname = $this->dohClient->resolve($testSub, 'CNAME', $proxy);

            $matchedThisProbe = false;

            if (!empty($resA['records'])) {
                foreach ($resA['records'] as $r) {
                    $wildcardIps[] = $r['data'];
                    $matchedThisProbe = true;
                }
            }
            if (!empty($resCname['records'])) {
                foreach ($resCname['records'] as $r) {
                    $wildcardCnames[] = trim($r['data'], '. ');
                    $matchedThisProbe = true;
                }
            }

            if ($matchedThisProbe) {
                $resolvedCount++;
            }
        }

        $uniqueIps = array_values(array_unique($wildcardIps));
        $uniqueCnames = array_values(array_unique($wildcardCnames));

        // 如果至少 2 个随机域名都能解析到值，断定存在泛解析
        $hasWildcard = $resolvedCount >= 2 && (!empty($uniqueIps) || !empty($uniqueCnames));

        return [
            'has_wildcard'    => $hasWildcard,
            'wildcard_ips'    => $uniqueIps,
            'wildcard_cnames' => $uniqueCnames,
            'tested_count'    => count($randomPrefixes)
        ];
    }

    /**
     * 判断解析记录是否命中泛解析黑名单
     */
    public function isWildcardMatch(string $value, array $wildcardData): bool
    {
        if (empty($wildcardData['has_wildcard'])) {
            return false;
        }

        $cleanVal = trim($value, '. ');
        if (in_array($cleanVal, $wildcardData['wildcard_ips'] ?? [], true)) {
            return true;
        }
        if (in_array($cleanVal, $wildcardData['wildcard_cnames'] ?? [], true)) {
            return true;
        }

        return false;
    }
}
