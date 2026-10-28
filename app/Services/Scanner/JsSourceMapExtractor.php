<?php

namespace App\Services\Scanner;

class JsSourceMapExtractor
{
    private const JS_FETCH_TIMEOUT = 4;
    private const MAX_JS_FILES = 5; // 单次只深入前 5 个核心 JS

    /**
     * 挖掘 Web 资产关联的 JS 与 Source Map
     */
    public function extractFromWeb(string $baseUrl, string $mainDomain, ?array $proxy = null): array
    {
        $discovered = [];
        $html = $this->fetchUrl($baseUrl, $proxy);
        if (!$html) {
            return [];
        }

        // 1. 从首页 HTML 正则直接提取域名前缀
        $discovered = array_merge($discovered, $this->matchDomainsInText($html, $mainDomain));

        // 2. 提取 <script src="..."> 路径
        if (preg_match_all('/<script[^>]+src=["\']([^"\']+)["\']/i', $html, $matches)) {
            $scripts = array_slice(array_unique($matches[1]), 0, self::MAX_JS_FILES);

            foreach ($scripts as $scriptUrl) {
                $fullScriptUrl = $this->resolveFullUrl($baseUrl, $scriptUrl);
                $jsContent = $this->fetchUrl($fullScriptUrl, $proxy);

                if ($jsContent) {
                    // 正则提取 JS 中的子域名
                    $discovered = array_merge($discovered, $this->matchDomainsInText($jsContent, $mainDomain));

                    // 3. 尝试探测 Source Map (.map)
                    $mapUrl = $fullScriptUrl . '.map';
                    $mapContent = $this->fetchUrl($mapUrl, $proxy);
                    if ($mapContent && str_starts_with(trim($mapContent), '{')) {
                        $json = json_decode($mapContent, true);
                        if (!empty($json['sourcesContent']) && is_array($json['sourcesContent'])) {
                            foreach ($json['sourcesContent'] as $srcCode) {
                                if (is_string($srcCode)) {
                                    $discovered = array_merge($discovered, $this->matchDomainsInText($srcCode, $mainDomain));
                                }
                            }
                        }
                    }
                }
            }
        }

        return array_values(array_unique($discovered));
    }

    private function matchDomainsInText(string $text, string $mainDomain): array
    {
        $pattern = '/\b([a-zA-Z0-9][a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9]\.)+' . preg_quote($mainDomain, '/') . '\b/i';
        $found = [];

        if (preg_match_all($pattern, $text, $matches)) {
            foreach ($matches[0] as $sub) {
                $sub = strtolower(trim($sub, '. '));
                if ($sub !== strtolower($mainDomain) && filter_var($sub, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                    $found[] = $sub;
                }
            }
        }
        return $found;
    }

    private function resolveFullUrl(string $base, string $rel): string
    {
        if (str_starts_with($rel, 'http://') || str_starts_with($rel, 'https://')) {
            return $rel;
        }
        if (str_starts_with($rel, '//')) {
            return 'https:' . $rel;
        }
        $parts = parse_url($base);
        $scheme = $parts['scheme'] ?? 'https';
        $host = $parts['host'] ?? '';
        return "{$scheme}://{$host}/" . ltrim($rel, '/');
    }

    private function fetchUrl(string $url, ?array $proxy): ?string
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, self::JS_FETCH_TIMEOUT);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 SRC-Crawler/1.2');

        if ($proxy) {
            curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");
        }

        $res = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return ($res && $code === 200) ? $res : null;
    }
}
