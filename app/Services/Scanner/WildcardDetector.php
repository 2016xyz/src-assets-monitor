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
     * 采用时间戳加盐的强随机探针，彻底避开权威与递归 DNS 的短时缓存
     */
    public function detect(string $mainDomain, ?array $proxy = null): array
    {
        $wildcardIps = [];
        $wildcardCnames = [];

        $timeSalt = dechex((int)(microtime(true) * 1000));
        $randomPrefixes = [
            "rnd-{$timeSalt}-" . bin2hex(random_bytes(4)),
            "nx-{$timeSalt}-" . bin2hex(random_bytes(4)),
            "chk-{$timeSalt}-" . bin2hex(random_bytes(4))
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

        $hasWildcard = $resolvedCount >= 2 && (!empty($uniqueIps) || !empty($uniqueCnames));

        return [
            'has_wildcard'    => $hasWildcard,
            'wildcard_ips'    => $uniqueIps,
            'wildcard_cnames' => $uniqueCnames,
            'tested_count'    => count($randomPrefixes)
        ];
    }

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
