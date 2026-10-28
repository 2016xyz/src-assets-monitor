<?php

namespace App\Services\Scanner;

use App\Core\Cache;
use App\Core\Crypto;
use App\Core\Database;

class AssetNameResolver
{
    private const MAX_TOTAL_TIMEOUT = 8; // 整体耗时上限 8s
    private const HTTP_PROBE_TIMEOUT = 5; // 单次 HTTP 探测超时 5s
    private const MAX_TITLE_LEN = 120;

    /**
     * 解析子域名的资产名称与来源
     */
    public function resolve(
        string $subdomain,
        string $mainDomain,
        string $recordType = 'A',
        ?string $recordValue = null,
        ?string $aliasName = null,
        ?array $proxy = null
    ): array {
        $startTime = microtime(true);
        $now = date('Y-m-d H:i:s');

        // 1. alias: 用户自定义别名 (最高优先级)
        if (!empty($aliasName) && trim($aliasName) !== '') {
            return [
                'asset_name'            => trim($aliasName),
                'asset_name_source'     => 'alias',
                'asset_name_updated_at' => $now
            ];
        }

        // 检查全局 HTTP 探针开关 (默认开启)
        $enableHttp = $this->isHttpProbeEnabled();

        // 2 & 3: http_title & http_server 探测
        if ($enableHttp && (microtime(true) - $startTime) < self::MAX_TOTAL_TIMEOUT) {
            $this->applyDomainRateLimit($mainDomain);

            $httpInfo = $this->probeHttp($subdomain, $mainDomain, $proxy);

            // 2. http_title
            if (!empty($httpInfo['title'])) {
                return [
                    'asset_name'            => $httpInfo['title'],
                    'asset_name_source'     => 'http_title',
                    'asset_name_updated_at' => $now
                ];
            }

            // 3. http_server
            if (!empty($httpInfo['server'])) {
                $serverName = $this->formatServerName($subdomain, $httpInfo['server']);
                return [
                    'asset_name'            => $serverName,
                    'asset_name_source'     => 'http_server',
                    'asset_name_updated_at' => $now
                ];
            }
        }

        // 4. cname: CNAME 记录目标
        if (strtoupper($recordType) === 'CNAME' && !empty($recordValue)) {
            $cleanCname = trim($recordValue, '. ');
            if ($cleanCname !== '' && $cleanCname !== $subdomain) {
                return [
                    'asset_name'            => mb_substr($cleanCname, 0, self::MAX_TITLE_LEN, 'UTF-8'),
                    'asset_name_source'     => 'cname',
                    'asset_name_updated_at' => $now
                ];
            }
        }

        // 5. ptr: 对解析 IP 做 gethostbyaddr 反查
        if ((microtime(true) - $startTime) < self::MAX_TOTAL_TIMEOUT && !empty($recordValue) && filter_var($recordValue, FILTER_VALIDATE_IP)) {
            $ptr = $this->resolvePtr($recordValue);
            if (!empty($ptr)) {
                return [
                    'asset_name'            => $ptr,
                    'asset_name_source'     => 'ptr',
                    'asset_name_updated_at' => $now
                ];
            }
        }

        // 6. hostname: 兜底使用子域名
        return [
            'asset_name'            => $subdomain,
            'asset_name_source'     => 'hostname',
            'asset_name_updated_at' => $now
        ];
    }

    /**
     * HTTP(S) 首页探针提取 Title 与 Server 响应头
     */
    private function probeHttp(string $subdomain, string $mainDomain, ?array $proxy): array
    {
        $result = ['title' => null, 'server' => null];

        // 优先探 HTTPS，若不可达再探 HTTP
        foreach (['https://', 'http://'] as $scheme) {
            $url = $scheme . $subdomain . '/';
            $resp = $this->fetchWithCurl($url, $mainDomain, $proxy);

            if ($resp['success']) {
                if (!empty($resp['server'])) {
                    $result['server'] = $resp['server'];
                }
                if (!empty($resp['body'])) {
                    $title = $this->extractTitle($resp['body']);
                    if (!empty($title)) {
                        $result['title'] = $title;
                        break;
                    }
                }
            }
        }

        return $result;
    }

    /**
     * 发起安全 cURL 请求 (限超时 5s、最多跟随 3 次重定向、不跳转到非目标主域)
     */
    private function fetchWithCurl(string $url, string $mainDomain, ?array $proxy): array
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, self::HTTP_PROBE_TIMEOUT);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 SRC-Monitor/1.2');

        if ($proxy) {
            $this->applyProxy($ch, $proxy);
        }

        $response = curl_exec($ch);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);

        if ($response === false) {
            return ['success' => false];
        }

        // 校验最终重定向地址是否跳出了主域名
        $finalHost = parse_url($effectiveUrl, PHP_URL_HOST);
        if ($finalHost && !str_ends_with(strtolower($finalHost), strtolower($mainDomain))) {
            return ['success' => false];
        }

        $headerText = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);

        $server = null;
        if (preg_match('/^Server:\s*(.+)$/mi', $headerText, $m)) {
            $server = trim($m[1]);
        } elseif (preg_match('/^X-Powered-By:\s*(.+)$/mi', $headerText, $m)) {
            $server = trim($m[1]);
        }

        return [
            'success' => true,
            'server'  => $server,
            'body'    => $body
        ];
    }

    /**
     * 标题提取与深度安全清洗 (自动转码 GBK/GB2312、防 XSS、实体解码再转义、截断 120 字)
     */
    private function extractTitle(string $html): ?string
    {
        $sample = substr($html, 0, 65536);

        if (!preg_match('/<title[^>]*>(.*?)<\/title>/is', $sample, $matches)) {
            return null;
        }

        $rawTitle = $matches[1];

        // 自动编码探测与转码 (支持 GBK / GB2312 / BIG5 等老旧资产编码无损转换)
        if (function_exists('mb_detect_encoding') && function_exists('mb_convert_encoding')) {
            $encoding = mb_detect_encoding($rawTitle, ['UTF-8', 'GBK', 'GB2312', 'BIG5', 'ISO-8859-1'], true);
            if ($encoding && strtoupper($encoding) !== 'UTF-8') {
                $rawTitle = mb_convert_encoding($rawTitle, 'UTF-8', $encoding);
            }
        }

        // 1. 过滤 HTML 标签
        $clean = strip_tags($rawTitle);

        // 2. 压缩多余连续空格与换行
        $clean = preg_replace('/\s+/', ' ', $clean);
        $clean = trim($clean);

        if ($clean === '') {
            return null;
        }

        // 3. HTML 实体解码后再严格转义存储 (防 XSS 双重防御)
        $decoded = html_entity_decode($clean, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $safeTitle = htmlspecialchars($decoded, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        // 4. 长度限制 120 字符
        if (mb_strlen($safeTitle, 'UTF-8') > self::MAX_TITLE_LEN) {
            $safeTitle = mb_substr($safeTitle, 0, self::MAX_TITLE_LEN - 1, 'UTF-8') . '…';
        }

        return $safeTitle;
    }

    private function formatServerName(string $subdomain, string $server): string
    {
        $cleanServer = preg_replace('/[^\w\.\-\/\s]/', '', $server);
        $cleanServer = trim(preg_replace('/\s+/', ' ', $cleanServer));
        $formatted = "{$subdomain} - {$cleanServer}";
        return mb_substr($formatted, 0, self::MAX_TITLE_LEN, 'UTF-8');
    }

    private function resolvePtr(string $ip): ?string
    {
        try {
            $ptr = @gethostbyaddr($ip);
            if ($ptr && $ptr !== $ip && filter_var($ptr, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                return mb_substr(trim($ptr), 0, self::MAX_TITLE_LEN, 'UTF-8');
            }
        } catch (\Throwable $e) {}
        return null;
    }

    private function isHttpProbeEnabled(): bool
    {
        try {
            $val = Database::fetchOne("SELECT value FROM settings WHERE `key` = 'enable_asset_name_http_probe'");
            return !empty($val) && (string)$val['value'] === '1';
        } catch (\Throwable $e) {
            return true;
        }
    }

    private function applyDomainRateLimit(string $mainDomain): void
    {
        $key = 'asset_probe_lock_' . md5($mainDomain);
        $lastTime = (float)Cache::get($key, 0);
        $elapsed = microtime(true) - $lastTime;
        if ($elapsed < 1.0) {
            usleep((int)((1.0 - $elapsed) * 1000000));
        }
        Cache::set($key, microtime(true), 10);
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
