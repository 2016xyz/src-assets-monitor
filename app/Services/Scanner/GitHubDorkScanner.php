<?php

namespace App\Services\Scanner;

use App\Core\Database;

class GitHubDorkScanner
{
    private const API_TIMEOUT = 5;

    /**
     * 针对主域名执行 GitHub Dorks 代码泄露搜寻
     *
     * @param string $mainDomain 目标主域名 (如 target.com)
     * @param array|null $proxy 出口代理
     * @return array 发现的合法子域名列表
     */
    public function search(string $mainDomain, ?array $proxy = null): array
    {
        $token = $this->getGitHubToken();
        $discovered = [];

        $dorks = [
            "\"{$mainDomain}\"",
            "\"{$mainDomain}\" internal",
            "\"{$mainDomain}\" staging",
            "\"{$mainDomain}\" api"
        ];

        foreach ($dorks as $q) {
            $url = "https://api.github.com/search/code?q=" . urlencode($q) . "&per_page=30";
            $headers = [
                'Accept: application/vnd.github.v3+json',
                'User-Agent: SRC-Asset-Discovery/1.2'
            ];
            if ($token) {
                $headers[] = "Authorization: token {$token}";
            }

            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($ch, CURLOPT_TIMEOUT, self::API_TIMEOUT);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);

            if ($proxy) {
                curl_setopt($ch, CURLOPT_PROXY, "{$proxy['host']}:{$proxy['port']}");
            }

            $res = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($res && $httpCode === 200) {
                $json = json_decode($res, true);
                if (!empty($json['items']) && is_array($json['items'])) {
                    foreach ($json['items'] as $item) {
                        // 提取 fragment 中的代码文本
                        $textSample = json_encode($item, JSON_UNESCAPED_UNICODE);
                        $subs = $this->extractValidDomains($textSample, $mainDomain);
                        $discovered = array_merge($discovered, $subs);
                    }
                }
            }

            // 遵守 GitHub API 速率限制
            usleep(500000); // 500ms
        }

        return array_values(array_unique($discovered));
    }

    /**
     * 正则提取并执行严苛的域名合法性校验
     */
    public function extractValidDomains(string $rawText, string $mainDomain): array
    {
        $pattern = '/\b([a-zA-Z0-9][a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9]\.)+' . preg_quote($mainDomain, '/') . '\b/i';
        $valid = [];

        if (preg_match_all($pattern, $rawText, $matches)) {
            foreach ($matches[0] as $candidate) {
                $candidate = strtolower(trim($candidate, '. '));
                if ($candidate === strtolower($mainDomain)) {
                    continue;
                }
                // 必须通过 FQDN 主机名校验
                if (filter_var($candidate, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                    $valid[] = $candidate;
                }
            }
        }

        return array_values(array_unique($valid));
    }

    private function getGitHubToken(): string
    {
        try {
            $row = Database::fetchOne("SELECT value FROM settings WHERE key = 'github_token'");
            return trim($row['value'] ?? '');
        } catch (\Throwable $e) {
            return '';
        }
    }
}
