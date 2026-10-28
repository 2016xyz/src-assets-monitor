<?php

namespace App\Services\Scanner;

use App\Core\Database;
use App\Services\Proxy\CircuitBreaker;
use App\Services\Proxy\DoHProxyClient;

class AssetDeepProbe
{
    private DoHProxyClient $dohClient;

    public function __construct()
    {
        $this->dohClient = new DoHProxyClient(new CircuitBreaker());
    }

    /**
     * 对单个子域名执行即时深度画像探查
     */
    public function inspect(string $subdomain, ?array $proxy = null): array
    {
        $portrait = [
            'subdomain'    => $subdomain,
            'timestamp'    => date('Y-m-d H:i:s'),
            'dns_records'  => [],
            'http_probe'   => null,
            'ssl_cert'     => null,
            'ip_info'      => null
        ];

        // 1. DNS 实时解析全记录 (A, CNAME)
        $aRes = $this->dohClient->resolve($subdomain, 'A', $proxy);
        $cnameRes = $this->dohClient->resolve($subdomain, 'CNAME', $proxy);

        $ips = [];
        if (!empty($aRes['records'])) {
            foreach ($aRes['records'] as $r) {
                $ips[] = $r['data'];
                $portrait['dns_records'][] = ['type' => 'A', 'value' => $r['data'], 'ttl' => $r['ttl']];
            }
        }
        if (!empty($cnameRes['records'])) {
            foreach ($cnameRes['records'] as $r) {
                $portrait['dns_records'][] = ['type' => 'CNAME', 'value' => $r['data'], 'ttl' => $r['ttl']];
            }
        }

        // 2. HTTP/HTTPS 状态与响应头探查
        $httpInfo = $this->probeWebStatus($subdomain, $proxy);
        $portrait['http_probe'] = $httpInfo;

        // 3. SSL/TLS 证书指纹与有效期解析
        $sslInfo = $this->extractCertificateDetails($subdomain);
        $portrait['ssl_cert'] = $sslInfo;

        // 4. IP 归属初筛
        if (!empty($ips)) {
            $portrait['ip_info'] = [
                'primary_ip' => $ips[0],
                'all_ips'    => $ips,
                'is_cdn'     => $this->detectCdn($subdomain, $ips)
            ];
        }

        return $portrait;
    }

    private function probeWebStatus(string $subdomain, ?array $proxy): array
    {
        $status = [
            'accessible'   => false,
            'scheme'       => null,
            'http_code'    => 0,
            'redirect_url' => null,
            'server'       => null,
            'title'        => null,
            'latency_ms'   => 0
        ];

        foreach (['https://', 'http://'] as $scheme) {
            $start = microtime(true);
            $url = $scheme . $subdomain . '/';
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SRC-Asset-Probe/1.2');

            if ($proxy) {
                curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");
            }

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            curl_close($ch);

            $duration = (int)((microtime(true) - $start) * 1000);

            if ($response !== false && $httpCode > 0) {
                $headers = substr($response, 0, $headerSize);
                $body = substr($response, $headerSize);

                $server = null;
                if (preg_match('/^Server:\s*(.+)$/mi', $headers, $m)) {
                    $server = trim($m[1]);
                }

                $title = null;
                if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $body, $m)) {
                    $title = trim(strip_tags($m[1]));
                    $title = htmlspecialchars(html_entity_decode($title, ENT_QUOTES | ENT_HTML5, 'UTF-8'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                }

                return [
                    'accessible'   => true,
                    'scheme'       => rtrim($scheme, ':/'),
                    'http_code'    => $httpCode,
                    'redirect_url' => $effectiveUrl !== $url ? $effectiveUrl : null,
                    'server'       => $server,
                    'title'        => $title,
                    'latency_ms'   => $duration
                ];
            }
        }

        return $status;
    }

    private function extractCertificateDetails(string $subdomain): ?array
    {
        try {
            $context = stream_context_create([
                'ssl' => [
                    'capture_peer_cert' => true,
                    'verify_peer'       => false,
                    'verify_peer_name'  => false,
                ]
            ]);

            $client = @stream_socket_client(
                "ssl://{$subdomain}:443",
                $errno,
                $errstr,
                3,
                STREAM_CLIENT_CONNECT,
                $context
            );

            if (!$client) {
                return null;
            }

            $params = stream_context_get_params($client);
            $cert = $params['options']['ssl']['peer_certificate'] ?? null;
            fclose($client);

            if (!$cert) {
                return null;
            }

            $certData = openssl_x509_parse($cert);
            $validFrom = $certData['validFrom_time_t'] ?? 0;
            $validTo = $certData['validTo_time_t'] ?? 0;
            $daysRemaining = (int)ceil(($validTo - time()) / 86400);

            $sanList = [];
            $sanStr = $certData['extensions']['subjectAltName'] ?? '';
            foreach (explode(',', $sanStr) as $part) {
                $part = trim($part);
                if (str_starts_with($part, 'DNS:')) {
                    $sanList[] = substr($part, 4);
                }
            }

            return [
                'common_name'    => $certData['subject']['CN'] ?? '',
                'issuer'         => $certData['issuer']['O'] ?? ($certData['issuer']['CN'] ?? '未知机构'),
                'valid_from'     => date('Y-m-d H:i:s', $validFrom),
                'valid_to'       => date('Y-m-d H:i:s', $validTo),
                'days_remaining' => $daysRemaining,
                'is_expired'     => $daysRemaining <= 0,
                'is_expiring_soon' => ($daysRemaining > 0 && $daysRemaining <= 14),
                'sans'           => array_slice($sanList, 0, 15)
            ];
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function detectCdn(string $subdomain, array $ips): bool
    {
        // 常见 CDN / 边缘防护 CNAME 或 IP 特征
        $cdnPatterns = ['eo.dnse2.com', 'cloudflare', 'cloudfront', 'fastly', 'kunlun', 'wscdns'];
        foreach ($cdnPatterns as $p) {
            if (str_contains(strtolower($subdomain), $p)) {
                return true;
            }
        }
        return false;
    }
}
