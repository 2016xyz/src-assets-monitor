<?php

namespace App\Services\Scanner;

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
     * 对单个子域名执行即时全景画像深度探查 (SSL / HTTP指纹 / IP归属地 / DNS链路)
     */
    public function inspect(string $subdomain, ?array $proxy = null): array
    {
        $subdomain = strtolower(trim($subdomain, '. '));

        $portrait = [
            'subdomain'   => $subdomain,
            'timestamp'   => date('Y-m-d H:i:s'),
            'dns_records' => [],
            'http_probe'  => null,
            'ssl_cert'    => null,
            'ip_geos'     => []
        ];

        // 1. DNS 深度解析全记录 (A / AAAA / CNAME / TXT / MX)
        $ips = [];
        $types = ['A', 'CNAME', 'TXT', 'MX'];
        foreach ($types as $t) {
            $res = $this->dohClient->resolve($subdomain, $t, $proxy);
            if (!empty($res['records'])) {
                foreach ($res['records'] as $r) {
                    $val = trim($r['data'], '. ');
                    $portrait['dns_records'][] = [
                        'type'  => $r['type'],
                        'value' => $val,
                        'ttl'   => $r['ttl'] ?? 300
                    ];
                    if ($r['type'] === 'A' && filter_var($val, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $ips[] = $val;
                    }
                }
            }
        }
        $ips = array_values(array_unique($ips));

        // 2. IP 归属地、运营商与 CDN 网络画像查询
        $ipGeoList = [];
        foreach (array_slice($ips, 0, 4) as $ip) {
            $ipGeoList[] = IpGeoResolver::resolve($ip, $proxy);
        }
        $portrait['ip_geos'] = $ipGeoList;

        // 3. HTTP / HTTPS 状态码与 Web 指纹探测
        $httpInfo = $this->probeWebFingerprints($subdomain, $proxy);
        $portrait['http_probe'] = $httpInfo;

        // 4. SSL/TLS 证书深度解析 (证书有效期/SAN/Issuer/指纹)
        $sslInfo = $this->extractCertificateDetails($subdomain);
        $portrait['ssl_cert'] = $sslInfo;

        return $portrait;
    }

    /**
     * 探查 HTTP/HTTPS 状态码、响应头与组件框架指纹
     */
    private function probeWebFingerprints(string $subdomain, ?array $proxy): array
    {
        $status = [
            'accessible'   => false,
            'scheme'       => null,
            'http_code'    => 0,
            'redirect_url' => null,
            'server'       => null,
            'powered_by'   => null,
            'frameworks'   => [],
            'title'        => null,
            'latency_ms'   => 0
        ];

        // 优先探测 HTTPS，若不可达或无响应则探测 HTTP
        foreach (['https://', 'http://'] as $scheme) {
            $start = microtime(true);
            $url = $scheme . $subdomain . '/';
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 6);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');

            if ($proxy) {
                curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");
            }

            $response = curl_exec($ch);
            $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            curl_close($ch);

            $duration = (int)((microtime(true) - $start) * 1000);

            if ($response !== false && $httpCode > 0) {
                $rawHeaders = substr($response, 0, $headerSize);
                $body = substr($response, $headerSize);

                // 提取 Web 服务器指纹
                $server = null;
                if (preg_match('/^Server:\s*(.+)$/mi', $rawHeaders, $m)) {
                    $server = trim($m[1]);
                }

                // 提取 X-Powered-By / 开发语言
                $poweredBy = null;
                if (preg_match('/^X-Powered-By:\s*(.+)$/mi', $rawHeaders, $m)) {
                    $poweredBy = trim($m[1]);
                }

                // 识别流行 Web 框架与技术栈
                $frameworks = [];
                if ($poweredBy) $frameworks[] = $poweredBy;
                if (preg_match('/wp-content|wp-includes/i', $body)) $frameworks[] = 'WordPress';
                if (preg_match('/laravel_session|XSRF-TOKEN/i', $rawHeaders)) $frameworks[] = 'Laravel';
                if (preg_match('/thinkphp|think_template/i', $rawHeaders . $body)) $frameworks[] = 'ThinkPHP';
                if (preg_match('/vue(\.global|\.runtime)?/i', $body)) $frameworks[] = 'Vue.js';
                if (preg_match('/react(\.production)?/i', $body)) $frameworks[] = 'React';
                if (preg_match('/__next/i', $body)) $frameworks[] = 'Next.js';
                if (preg_match('/swagger-ui|springfox/i', $body)) $frameworks[] = 'Swagger API Docs';

                // 提取网页 Title 标题 (自动处理 GBK/UTF-8 字符集转换)
                $title = null;
                if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $body, $m)) {
                    $rawTitle = trim(strip_tags($m[1]));
                    $encoding = mb_detect_encoding($rawTitle, ['UTF-8', 'GBK', 'GB2312', 'BIG5'], true);
                    if ($encoding && $encoding !== 'UTF-8') {
                        $rawTitle = mb_convert_encoding($rawTitle, 'UTF-8', $encoding);
                    }
                    $title = htmlspecialchars(html_entity_decode($rawTitle, ENT_QUOTES | ENT_HTML5, 'UTF-8'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                }

                return [
                    'accessible'   => true,
                    'scheme'       => rtrim($scheme, ':/'),
                    'http_code'    => $httpCode,
                    'redirect_url' => ($httpCode >= 300 && $httpCode < 400 && preg_match('/^Location:\s*(.+)$/mi', $rawHeaders, $lm)) ? trim($lm[1]) : null,
                    'server'       => $server,
                    'powered_by'   => $poweredBy,
                    'frameworks'   => array_values(array_unique($frameworks)),
                    'title'        => $title,
                    'latency_ms'   => $duration
                ];
            }
        }

        return $status;
    }

    /**
     * 深度解析 TLS/SSL 证书信息 (有效期/SAN扩展/Issuer机构/SHA256指纹)
     */
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

            // 提取备用名称 SAN 集合
            $sanList = [];
            $sanStr = $certData['extensions']['subjectAltName'] ?? '';
            foreach (explode(',', $sanStr) as $part) {
                $part = trim($part);
                if (str_starts_with($part, 'DNS:')) {
                    $sanList[] = substr($part, 4);
                }
            }

            // 导出 SHA256 证书指纹
            openssl_x509_export($cert, $pem);
            $fingerprintSha256 = $pem ? hash('sha256', base64_decode(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\r", "\n"], '', $pem))) : null;

            return [
                'common_name'      => $certData['subject']['CN'] ?? '',
                'issuer'           => $certData['issuer']['O'] ?? ($certData['issuer']['CN'] ?? '未知签发机构'),
                'valid_from'       => date('Y-m-d H:i:s', $validFrom),
                'valid_to'         => date('Y-m-d H:i:s', $validTo),
                'days_remaining'   => $daysRemaining,
                'is_expired'       => $daysRemaining <= 0,
                'is_expiring_soon' => ($daysRemaining > 0 && $daysRemaining <= 14),
                'signature_type'   => $certData['signatureTypeSN'] ?? 'RSA-SHA256',
                'fingerprint_sha256' => $fingerprintSha256,
                'sans'             => array_slice($sanList, 0, 20)
            ];
        } catch (\Throwable $e) {
            return null;
        }
    }
}
