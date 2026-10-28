<?php

namespace App\Services\Scanner;

use App\Core\Cache;
use App\Core\Database;

class PassiveCollectorPool
{
    private const SOURCE_TIMEOUT = 8; // 单源超时 8s
    private const TOTAL_TIMEOUT = 18; // 并发汇总总超时 18s

    /**
     * 并发收集全部多轨被动源 (SubdomainCenter / crt.sh / CertSpotter / RapidDNS / ThreatMiner / DNS权威记录 / TLS SAN)
     *
     * @param string $mainDomain 目标主域名 (如 2016xlx.cn)
     * @param array|null $proxy 域名出站代理
     * @return array ['subdomain.example.com' => ['sources' => ['crt.sh', 'subdomain_center']]]
     */
    public function collectAll(string $mainDomain, ?array $proxy = null): array
    {
        $normalizedDomain = strtolower(trim($mainDomain, '. '));
        $resultsMap = []; // [subdomain => ['sources' => [...]]]

        // 1. 核心高速源：SubdomainCenter (免密直连，历史覆盖率极高)
        $subcenterSubs = $this->collectFromSubdomainCenter($normalizedDomain, $proxy);
        foreach ($subcenterSubs as $sub) {
            $this->appendResult($resultsMap, $sub, 'subdomain_center');
        }

        // 2. 核心证书源：crt.sh 双轨抓取 (同时尝试 dNSName 与普通查询，HTML 与 JSON 兼容)
        $crtSubs = $this->collectFromCrtSh($normalizedDomain, $proxy);
        foreach ($crtSubs as $sub) {
            $this->appendResult($resultsMap, $sub, 'crt.sh');
        }

        // 3. cURL multi 并发查询外部各大聚合 API 源 (CertSpotter/RapidDNS/ThreatMiner/Wayback/URLScan)
        $multi = curl_multi_init();
        $handles = [];
        $sourcesConfig = $this->getSourcesConfig($normalizedDomain);

        foreach ($sourcesConfig as $sourceName => $cfg) {
            $ch = curl_init($cfg['url']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, self::SOURCE_TIMEOUT);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 4);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');

            if (!empty($cfg['headers'])) {
                curl_setopt($ch, CURLOPT_HTTPHEADER, $cfg['headers']);
            }
            if ($proxy) {
                $this->applyProxy($ch, $proxy);
            }

            curl_multi_add_handle($multi, $ch);
            $handles[$sourceName] = $ch;
        }

        $active = null;
        $start = microtime(true);
        do {
            $mrc = curl_multi_exec($multi, $active);
            if ($active) {
                curl_multi_select($multi, 0.05);
            }
            if ((microtime(true) - $start) > self::TOTAL_TIMEOUT) {
                break; // 超时保护
            }
        } while ($active && $mrc == CURLM_OK);

        foreach ($handles as $sourceName => $ch) {
            $content = curl_multi_getcontent($ch);
            $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_multi_remove_handle($multi, $ch);
            curl_close($ch);

            if ($httpCode === 200 && !empty($content)) {
                $subs = $this->parseSourceResponse($sourceName, $content, $normalizedDomain);
                foreach ($subs as $sub) {
                    $this->appendResult($resultsMap, $sub, $sourceName);
                }
            }
        }
        curl_multi_close($multi);

        // 4. DNS 权威记录挖掘 (NS / MX / TXT SPF 内部主机与别名关联)
        $dnsZoneSubs = $this->extractDnsZoneHostnames($normalizedDomain);
        foreach ($dnsZoneSubs as $sub) {
            $this->appendResult($resultsMap, $sub, 'dns_zone');
        }

        // 5. TLS SAN 证书扩展直连探针
        $sanSubs = $this->extractTlsSan($normalizedDomain, $proxy);
        foreach ($sanSubs as $sub) {
            $this->appendResult($resultsMap, $sub, 'tls_san');
        }

        return $resultsMap;
    }

    /**
     * SubdomainCenter 专用解析
     */
    private function collectFromSubdomainCenter(string $domain, ?array $proxy): array
    {
        $discovered = [];
        $url = "https://api.subdomain.center/?domain=" . urlencode($domain);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 6);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SRC-Security-Scanner/1.2');
        if ($proxy) {
            $this->applyProxy($ch, $proxy);
        }
        $res = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($code === 200 && $res) {
            $json = json_decode($res, true);
            if (is_array($json)) {
                $discovered = $json;
            }
        }

        return $this->normalizeSubdomains($discovered, $domain);
    }

    /**
     * 专属 crt.sh 弹性抓取：尝试 dNSName 参数与通用匹配
     */
    private function collectFromCrtSh(string $domain, ?array $proxy): array
    {
        $discovered = [];
        $urls = [
            "https://crt.sh/?dNSName=" . urlencode("%.{$domain}"),
            "https://crt.sh/?q=" . urlencode($domain)
        ];

        foreach ($urls as $url) {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 8);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 4);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
            if ($proxy) {
                $this->applyProxy($ch, $proxy);
            }
            $html = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200 && !empty($html)) {
                $pattern = '/([a-zA-Z0-9_\-\.]+\.' . preg_quote($domain, '/') . ')/i';
                if (preg_match_all($pattern, $html, $matches)) {
                    foreach ($matches[1] as $sub) {
                        $discovered[] = $sub;
                    }
                }
            }
            if (count($discovered) > 10) break;
        }

        return $this->normalizeSubdomains($discovered, $domain);
    }

    /**
     * 定义外部各大权威被动数据源配置
     */
    private function getSourcesConfig(string $domain): array
    {
        $otxKey = $this->getSetting('otx_api_key', '');
        $otxHeaders = $otxKey ? ["X-OTX-API-KEY: {$otxKey}"] : [];

        return [
            'certspotter' => [
                'url'     => "https://api.certspotter.com/v1/issuances?domain={$domain}&include_subdomains=true&expand=dns_names",
                'headers' => []
            ],
            'rapiddns' => [
                'url'     => "https://rapiddns.io/subdomain/{$domain}",
                'headers' => []
            ],
            'threatminer' => [
                'url'     => "https://api.threatminer.org/v2/domain.php?q={$domain}&rt=5",
                'headers' => []
            ],
            'hackertarget' => [
                'url'     => "https://api.hackertarget.com/hostsearch/?q={$domain}",
                'headers' => []
            ],
            'alienvault_otx' => [
                'url'     => "https://otx.alienvault.com/api/v1/indicators/domain/{$domain}/passive_dns",
                'headers' => $otxHeaders
            ],
            'urlscan' => [
                'url'     => "https://urlscan.io/api/v1/search/?q=domain:{$domain}",
                'headers' => []
            ]
        ];
    }

    /**
     * 从主域名的 DNS 权威记录中提取子域名 (NS/MX/TXT/SPF 内部主机关联)
     */
    private function extractDnsZoneHostnames(string $domain): array
    {
        $candidates = [];
        try {
            $mxRecords = @dns_get_record($domain, DNS_MX);
            if (is_array($mxRecords)) {
                foreach ($mxRecords as $mx) {
                    if (!empty($mx['target']) && str_ends_with(strtolower($mx['target']), '.' . $domain)) {
                        $candidates[] = $mx['target'];
                    }
                }
            }

            $txtRecords = @dns_get_record($domain, DNS_TXT);
            if (is_array($txtRecords)) {
                foreach ($txtRecords as $txt) {
                    $txtVal = $txt['txt'] ?? '';
                    if (preg_match_all('/([a-zA-Z0-9_\-\.]+\.' . preg_quote($domain, '/') . ')/i', $txtVal, $m)) {
                        $candidates = array_merge($candidates, $m[1]);
                    }
                }
            }
        } catch (\Throwable $e) {}

        return $this->normalizeSubdomains($candidates, $domain);
    }

    /**
     * 解析各数据源响应并归一化
     */
    private function parseSourceResponse(string $sourceName, string $content, string $mainDomain): array
    {
        $extracted = [];

        try {
            switch ($sourceName) {
                case 'certspotter':
                    $json = json_decode($content, true);
                    if (is_array($json)) {
                        foreach ($json as $row) {
                            $names = $row['dns_names'] ?? [];
                            foreach ($names as $n) {
                                $extracted[] = $n;
                            }
                        }
                    }
                    break;

                case 'rapiddns':
                    if (preg_match_all('/<td>([a-zA-Z0-9.-]+\.' . preg_quote($mainDomain, '/') . ')<\/td>/i', $content, $m)) {
                        $extracted = array_merge($extracted, $m[1]);
                    }
                    break;

                case 'threatminer':
                    $json = json_decode($content, true);
                    if (!empty($json['results']) && is_array($json['results'])) {
                        foreach ($json['results'] as $sub) {
                            $extracted[] = $sub;
                        }
                    }
                    break;

                case 'hackertarget':
                    $lines = explode("\n", $content);
                    foreach ($lines as $line) {
                        $parts = explode(',', trim($line));
                        if (!empty($parts[0])) {
                            $extracted[] = $parts[0];
                        }
                    }
                    break;

                case 'alienvault_otx':
                    $json = json_decode($content, true);
                    if (!empty($json['passive_dns']) && is_array($json['passive_dns'])) {
                        foreach ($json['passive_dns'] as $row) {
                            if (!empty($row['hostname'])) {
                                $extracted[] = $row['hostname'];
                            }
                        }
                    }
                    break;

                case 'urlscan':
                    $json = json_decode($content, true);
                    if (!empty($json['results']) && is_array($json['results'])) {
                        foreach ($json['results'] as $res) {
                            $pageDomain = $res['page']['domain'] ?? null;
                            if ($pageDomain) $extracted[] = $pageDomain;
                        }
                    }
                    break;
            }
        } catch (\Throwable $e) {}

        return $this->normalizeSubdomains($extracted, $mainDomain);
    }

    /**
     * TLS SAN 兜底提取
     */
    private function extractTlsSan(string $mainDomain, ?array $proxy): array
    {
        $sanList = [];
        try {
            $context = stream_context_create([
                'ssl' => [
                    'capture_peer_cert' => true,
                    'verify_peer'       => false,
                    'verify_peer_name'  => false,
                ]
            ]);

            $client = @stream_socket_client(
                "ssl://{$mainDomain}:443",
                $errno,
                $errstr,
                3,
                STREAM_CLIENT_CONNECT,
                $context
            );

            if ($client) {
                $params = stream_context_get_params($client);
                $cert = $params['options']['ssl']['peer_certificate'] ?? null;
                if ($cert) {
                    $certData = openssl_x509_parse($cert);
                    $sanStr = $certData['extensions']['subjectAltName'] ?? '';
                    foreach (explode(',', $sanStr) as $part) {
                        $part = trim($part);
                        if (str_starts_with($part, 'DNS:')) {
                            $sanList[] = substr($part, 4);
                        }
                    }
                }
                fclose($client);
            }
        } catch (\Throwable $e) {}

        return $this->normalizeSubdomains($sanList, $mainDomain);
    }

    public function normalizeSubdomains(array $rawList, string $mainDomain): array
    {
        $clean = [];
        $mainDomain = strtolower(trim($mainDomain, '. '));

        foreach ($rawList as $item) {
            $sub = strtolower(trim($item));
            if (str_starts_with($sub, '*.')) {
                $sub = substr($sub, 2);
            }
            $sub = rtrim($sub, '.');

            if ($sub === '' || $sub === $mainDomain) {
                continue;
            }

            if (!str_ends_with($sub, '.' . $mainDomain)) {
                continue;
            }

            if (filter_var($sub, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                $clean[] = $sub;
            }
        }

        return array_values(array_unique($clean));
    }

    private function appendResult(array &$pool, string $sub, string $source): void
    {
        if (!isset($pool[$sub])) {
            $pool[$sub] = ['sources' => [$source]];
        } elseif (!in_array($source, $pool[$sub]['sources'], true)) {
            $pool[$sub]['sources'][] = $source;
        }
    }

    private function getSetting(string $key, string $default = ''): string
    {
        try {
            $row = Database::fetchOne("SELECT value FROM settings WHERE `key` = ?", [$key]);
            return $row['value'] ?? $default;
        } catch (\Throwable $e) {
            return $default;
        }
    }

    private function applyProxy($ch, array $proxy): void
    {
        $proto = strtolower($proxy['protocol'] ?? 'http');
        $host = $proxy['host'];
        $port = (int)$proxy['port'];

        $proxyType = CURLPROXY_HTTP;
        if ($proto === 'https') {
            $proxyType = CURLPROXY_HTTPS;
        } elseif ($proto === 'socks5') {
            $proxyType = CURLPROXY_SOCKS5;
        } elseif ($proto === 'socks5h') {
            $proxyType = CURLPROXY_SOCKS5_HOSTNAME;
        }

        curl_setopt($ch, CURLOPT_PROXYTYPE, $proxyType);
        curl_setopt($ch, CURLOPT_PROXY, "{$host}:{$port}");
    }
}
