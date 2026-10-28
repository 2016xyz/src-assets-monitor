<?php

namespace App\Services\Scanner;

class BucketTakeoverDetector
{
    private array $bucketPatterns = [
        's3.amazonaws.com'   => 'NoSuchBucket',
        'storage.googleapis' => 'The specified bucket does not exist',
        'blob.core.windows'  => 'BlobNotFound'
    ];

    /**
     * 对候选子域名或云存储 CNAME 目标执行只读只检测 (严格禁止写入)
     *
     * @param string $cnameTarget CNAME目标 (如 org-assets.s3.amazonaws.com)
     * @param array|null $proxy 出口代理
     * @return array ['is_dangling_bucket' => bool, 'reason' => string|null]
     */
    public function checkBucketStatus(string $cnameTarget, ?array $proxy = null): array
    {
        $target = strtolower(trim($cnameTarget, '. '));
        $matchedPattern = null;
        $signature = null;

        foreach ($this->bucketPatterns as $pattern => $sig) {
            if (str_contains($target, $pattern)) {
                $matchedPattern = $pattern;
                $signature = $sig;
                break;
            }
        }

        if (!$matchedPattern) {
            return ['is_dangling_bucket' => false, 'reason' => null];
        }

        // 只读 GET 请求探测是否存在 404 NoSuchBucket
        $url = "https://{$target}/";
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 4);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SRC-Monitor/1.2');

        if ($proxy) {
            curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");
        }

        $res = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($res && ($httpCode === 404 || str_contains($res, $signature))) {
            return [
                'is_dangling_bucket' => true,
                'reason'             => "云存储桶未创建或已释放 ({$signature})，存在严重 CNAME 桶接管风险"
            ];
        }

        return ['is_dangling_bucket' => false, 'reason' => null];
    }

    /**
     * 基于主域名自动生成常见业务云存储桶候选字典
     */
    public function generateBucketCandidates(string $mainDomain): array
    {
        $parts = explode('.', $mainDomain);
        $org = $parts[0]; // 如 example

        $suffixes = [
            '', '-backup', '-dev', '-staging', '-prod',
            '-assets', '-uploads', '-logs', '-static',
            '-media', '-public', '-data'
        ];

        $candidates = [];
        foreach ($suffixes as $sfx) {
            $candidates[] = "{$org}{$sfx}";
        }
        return $candidates;
    }
}
