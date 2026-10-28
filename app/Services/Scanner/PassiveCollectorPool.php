<?php

namespace App\Services\Scanner;

use App\Core\Cache;
use App\Core\Database;

class PassiveCollectorPool
{
    private const SOURCE_TIMEOUT = 8; // 单源超时 8s
    private const TOTAL_TIMEOUT = 18; // 并发汇总总超时 18s

    /**
     * 并发收集全部多轨被动源 (CT 日志 / 历史快照 / 搜索引擎 / DNS 关联)
     *
     * @param string $mainDomain 目标主域名 (如 2016xlx.cn)
     * @param array|null $proxy 域名出站代理
     * @return array ['subdomain.example.com' => ['sources' => ['crt.sh', 'certspotter']]]
     */
    public function collectAll(string $mainDomain, ?array $proxy = null): array
    {
        $normalizedDomain = strtolower(trim($mainDomain, '. '));
        $resultsMap = []; // [subdomain => ['sources' => [...]]]

        // 1. 优先抓取 crt.sh (HTML 双轨抓取，彻底避免 JSON 接口频发 502 Bad Gateway 丢数据)
        $crtSubs = $this->collectFromCrtSh($normalizedDomain, $proxy);
        foreach ($crtSubs as $sub) {
            $this->appendResult($resultsMap, $sub, 'crt.sh');
        }

        // 2. cURL multi 并发查询外部各大聚合 API 源
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

        // 3. 搜索引擎被动嗅探 (Bing / 百度搜索 site:domain 爬虫)
        $searchSubs = $this->crawlSearchEngines($normalizedDomain, $proxy);
        foreach ($searchSubs as $sub) {
            $this->appendResult($resultsMap, $sub, 'search_engine');
        }

        // 4. DNS 权威记录挖掘 (NS / MX / TXT SPF 内部关联)
        $dnsZoneSubs = $this->extractDnsZoneHostnames($normalizedDomain);
        foreach ($dnsZoneSubs as $sub) {
            $this->appendResult($resultsMap, $sub, 'dns_zone');
        }

        // 5. TLS SAN 直连探针
        $sanSubs = $this->extractTlsSan($normalizedDomain, $proxy);
        foreach ($sanSubs as $sub) {
            $this->appendResult($resultsMap, $sub, 'tls_san');
        }

        return $resultsMap;
    }

    /**
     * 专属 crt.sh 弹性抓取：先尝试 HTML 网页检索 (极度稳定，不卡 502)，若不足再补充 JSON
     */
    private function collectFromCrtSh(string $domain, ?array $proxy): array
    {
        $discovered = [];
        $urls = [
            "https://crt.sh/?q=" . urlencode($domain),
            "https://crt.sh/?q=" . urlencode("%.{$domain}")
        ];

        foreach ($urls as $url) {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 7);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
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
                // 正则精准匹配 HTML 页面中所有属于该主域的 FQDN
                $pattern = '/([a-zA-Z0-9_\-\.]+\.' . preg_quote($domain, '/') . ')/i';
                if (preg_match_all($pattern, $html, $matches)) {
                    foreach ($matches[1] as $sub) {
                        $discovered[] = $sub;
                    }
                }
            }
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
            'threatminer' => [
                'url'     => "https://api.threatminer.org/v2/domain.php?q={$domain}&rt=5",
                'headers' => []
            ],
            'certspotter' => [
                'url'     => "https://api.certspotter.com/v1/issuances?domain={$domain}&include_subdomains=true&expand=dns_names",
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
            'rapiddns' => [
                'url'     => "https://rapiddns.io/subdomain/{$domain}",
                'headers' => []
            ],
            'anubisdb' => [
                'url'     => "https://jldc.me/anubis/subdomains/{$domain}",
                'headers' => []
            ],
            'wayback_archive' => [
                'url'     => "http://web.archive.org/cdx/search/cdx?url=*.{$domain}&output=json&collapse=urlkey",
                'headers' => []
            ],
            'urlscan' => [
                'url'     => "https://urlscan.io/api/v1/search/?q=domain:{$domain}",
                'headers' => []
            ]
        ];
    }

    /**
     * 搜索引擎被动嗅探 (Bing Web Crawler)
     */
    private function crawlSearchEngines(string $domain, ?array $proxy): array
    {
        $subs = [];
        $bingUrl = "https://www.bing.com/search?q=" . urlencode("domain:{$domain} -www.{$domain}");

        $ch = curl_init($bingUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
        if ($proxy) {
            $this->applyProxy($ch, $proxy);
        }
        $html = curl_exec($ch);
        curl_close($ch);

        if ($html) {
            $pattern = '/https?:\/\/([a-zA-Z0-9_\-\.]+\.' . preg_quote($domain, '/') . ')/i';
            if (preg_match_all($pattern, $html, $m)) {
                $subs = array_merge($subs, $m[1]);
            }
        }

        return $this->normalizeSubdomains($subs, $domain);
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
                case 'threatminer':
                    $json = json_decode($content, true);
                    if (!empty($json['results']) && is_array($json['results'])) {
                        foreach ($json['results'] as $sub) {
                            $extracted[] = $sub;
                        }
                    }
                    break;

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

                case 'rapiddns':
                    if (preg_match_all('/<td>([a-zA-Z0-9.-]+\.' . preg_quote($mainDomain, '/') . ')<\/td>/i', $content, $m)) {
                        $extracted = array_merge($extracted, $m[1]);
                    }
                    break;

                case 'anubisdb':
                    $json = json_decode($content, true);
                    if (is_array($json)) {
                        foreach ($json as $item) {
                            $extracted[] = $item;
                        }
                    }
                    break;

                case 'wayback_archive':
                    $json = json_decode($content, true);
                    if (is_array($json)) {
                        foreach ($json as $idx => $row) {
                            if ($idx === 0) continue;
                            $url = $row[2] ?? '';
                            $host = parse_url($url, PHP_URL_HOST);
                            if ($host) $extracted[] = $host;
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
            // 剥离通配符前缀
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
