<?php

namespace App\Services\Scanner;

use App\Core\Cache;
use App\Core\Crypto;
use App\Core\Database;

class PassiveCollectorPool
{
    private const SOURCE_TIMEOUT = 5; // 单源超时 5s
    private const TOTAL_TIMEOUT = 12; // 并发汇总总超时 12s

    /**
     * 并发收集全部被动源
     *
     * @param string $mainDomain 目标主域名 (如 example.com)
     * @param array|null $proxy 域名出站代理
     * @return array ['subdomain.example.com' => ['sources' => ['crt.sh', 'hackertarget']]]
     */
    public function collectAll(string $mainDomain, ?array $proxy = null): array
    {
        $normalizedDomain = strtolower(trim($mainDomain, '. '));
        $multi = curl_multi_init();
        $handles = [];

        // 1. 构建各 HTTP 源请求
        $sourcesConfig = $this->getSourcesConfig($normalizedDomain);
        foreach ($sourcesConfig as $sourceName => $cfg) {
            $ch = curl_init($cfg['url']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, self::SOURCE_TIMEOUT);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SRC-Security-Scanner/1.2');

            if (!empty($cfg['headers'])) {
                curl_setopt($ch, CURLOPT_HTTPHEADER, $cfg['headers']);
            }
            if ($proxy) {
                $this->applyProxy($ch, $proxy);
            }

            curl_multi_add_handle($multi, $ch);
            $handles[$sourceName] = $ch;
        }

        // 2. cURL multi 并发执行
        $active = null;
        $start = microtime(true);
        do {
            $mrc = curl_multi_exec($multi, $active);
            if ($active) {
                curl_multi_select($multi, 0.05);
            }
            if ((microtime(true) - $start) > self::TOTAL_TIMEOUT) {
                break; // 触发总超时保护
            }
        } while ($active && $mrc == CURLM_OK);

        $resultsMap = []; // [subdomain => ['sources' => [...]]]

        // 3. 读取并解析各源应答
        foreach ($handles as $sourceName => $ch) {
            $content = curl_multi_getcontent($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_multi_remove_handle($multi, $ch);
            curl_close($ch);

            if ($httpCode === 200 && !empty($content)) {
                $subs = $this->parseSourceResponse($sourceName, $content, $normalizedDomain);
                foreach ($subs as $sub) {
                    if (!isset($resultsMap[$sub])) {
                        $resultsMap[$sub] = ['sources' => [$sourceName]];
                    } elseif (!in_array($sourceName, $resultsMap[$sub]['sources'], true)) {
                        $resultsMap[$sub]['sources'][] = $sourceName;
                    }
                }
            }
        }
        curl_multi_close($multi);

        // 4. TLS SAN 兜底直连探测 (独立执行，不阻塞 HTTP multi)
        $sanSubs = $this->extractTlsSan($normalizedDomain, $proxy);
        foreach ($sanSubs as $sub) {
            if (!isset($resultsMap[$sub])) {
                $resultsMap[$sub] = ['sources' => ['tls_san']];
            } elseif (!in_array('tls_san', $resultsMap[$sub]['sources'], true)) {
                $resultsMap[$sub]['sources'][] = 'tls_san';
            }
        }

        return $resultsMap;
    }

    /**
     * 定义 8+ 被动数据源配置
     */
    private function getSourcesConfig(string $domain): array
    {
        $otxKey = $this->getSetting('otx_api_key', '');
        $otxHeaders = $otxKey ? ["X-OTX-API-KEY: {$otxKey}"] : [];

        return [
            'crt.sh' => [
                'url' => "https://crt.sh/?q=%25.{$domain}&output=json",
                'headers' => []
            ],
            'certspotter' => [
                'url' => "https://api.certspotter.com/v1/issuances?domain={$domain}&include_subdomains=true&expand=dns_names",
                'headers' => []
            ],
            'hackertarget' => [
                'url' => "https://api.hackertarget.com/hostsearch/?q={$domain}",
                'headers' => []
            ],
            'alienvault_otx' => [
                'url' => "https://otx.alienvault.com/api/v1/indicators/domain/{$domain}/passive_dns",
                'headers' => $otxHeaders
            ],
            'wayback_archive' => [
                'url' => "http://web.archive.org/cdx/search/cdx?url=*.{$domain}&output=json&collapse=urlkey",
                'headers' => []
            ],
            'anubisdb' => [
                'url' => "https://jldc.me/anubis/subdomains/{$domain}",
                'headers' => []
            ],
            'rapiddns' => [
                'url' => "https://rapiddns.io/subdomain/{$domain}",
                'headers' => []
            ],
            'urlscan' => [
                'url' => "https://urlscan.io/api/v1/search/?q=domain:{$domain}",
                'headers' => []
            ]
        ];
    }

    /**
     * 解析各数据源响应并归一化
     */
    private function parseSourceResponse(string $sourceName, string $content, string $mainDomain): array
    {
        $extracted = [];

        try {
            switch ($sourceName) {
                case 'crt.sh':
                    $json = json_decode($content, true);
                    if (is_array($json)) {
                        foreach ($json as $row) {
                            $nv = $row['name_value'] ?? '';
                            foreach (explode("\n", $nv) as $line) {
                                $extracted[] = $line;
                            }
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

                case 'wayback_archive':
                    $json = json_decode($content, true);
                    if (is_array($json)) {
                        foreach ($json as $idx => $row) {
                            if ($idx === 0) continue; // 第一行为头部说明
                            $url = $row[2] ?? '';
                            $host = parse_url($url, PHP_URL_HOST);
                            if ($host) $extracted[] = $host;
                        }
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

                case 'rapiddns':
                    // 正则提取 HTML 表格内子域名
                    if (preg_match_all('/<td>([a-zA-Z0-9.-]+\.' . preg_quote($mainDomain, '/') . ')<\/td>/i', $content, $m)) {
                        $extracted = array_merge($extracted, $m[1]);
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
        } catch (\Throwable $e) {
            // 单源解析异常静默捕获
        }

        return $this->normalizeSubdomains($extracted, $mainDomain);
    }

    /**
     * TLS SAN 兜底提取：对主域名发起 TLS 连接读取证书 SAN 扩展
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
                    // 格式: DNS:example.com, DNS:*.example.com, DNS:api.example.com
                    foreach (explode(',', $sanStr) as $part) {
                        $part = trim($part);
                        if (str_starts_with($part, 'DNS:')) {
                            $sanList[] = substr($part, 4);
                        }
                    }
                }
                fclose($client);
            }
        } catch (\Throwable $e) {
            // 静默降级
        }

        return $this->normalizeSubdomains($sanList, $mainDomain);
    }

    /**
     * 统一归一化去重规则：小写、去尾部点、剔除通配符 *.、剔除非本主域
     */
    public function normalizeSubdomains(array $rawList, string $mainDomain): array
    {
        $clean = [];
        $mainDomain = strtolower(trim($mainDomain, '. '));

        foreach ($rawList as $item) {
            $sub = strtolower(trim($item));
            $sub = ltrim($sub, '*.');
            $sub = rtrim($sub, '.');

            if ($sub === '' || $sub === $mainDomain) {
                continue;
            }

            // 必须以主域结尾
            if (!str_ends_with($sub, '.' . $mainDomain)) {
                continue;
            }

            // 合法 FQDN 格式
            if (filter_var($sub, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                $clean[] = $sub;
            }
        }

        return array_values(array_unique($clean));
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
        $proxyType = match ($proto) {
            'https'   => CURLPROXY_HTTPS,
            'socks5'  => CURLPROXY_SOCKS5,
            'socks5h' => CURLPROXY_SOCKS5_HOSTNAME,
            default   => CURLPROXY_HTTP
        };
        curl_setopt($ch, CURLOPT_PROXYTYPE, $proxyType);
        curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");

        if (!empty($proxy['auth_user'])) {
            $pass = !empty($proxy['auth_pass_encrypted']) ? Crypto::decrypt($proxy['auth_pass_encrypted']) : '';
            curl_setopt($ch, CURLOPT_PROXYUSERPWD, "{$proxy['auth_user']}:{$pass}");
        }
    }
}
