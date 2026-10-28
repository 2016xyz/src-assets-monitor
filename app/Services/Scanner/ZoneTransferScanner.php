<?php

namespace App\Services\Scanner;

use App\Core\Database;
use App\Services\Proxy\DoHProxyClient;

class ZoneTransferScanner
{
    private const AXFR_TIMEOUT = 3; // 3s 超时，不重试
    private DoHProxyClient $dohClient;

    public function __construct(DoHProxyClient $doh)
    {
        $this->dohClient = $doh;
    }

    /**
     * 探测目标主域名是否存在 DNS 区域传送 (AXFR) 配置泄漏
     *
     * @param string $mainDomain 目标主域名
     * @param array|null $proxy 出口代理
     * @return array ['vulnerable' => bool, 'records' => ['sub1.target.com', ...], 'ns_checked' => [...]]
     */
    public function probeAxfr(string $mainDomain, ?array $proxy = null): array
    {
        // 1. 查询权威 NS 记录
        $nsRes = $this->dohClient->resolve($mainDomain, 'NS', $proxy);
        if (empty($nsRes['records'])) {
            return ['vulnerable' => false, 'records' => [], 'ns_checked' => []];
        }

        $nsList = [];
        foreach ($nsRes['records'] as $r) {
            $nsList[] = trim($r['data'], '. ');
        }
        $nsList = array_values(array_unique($nsList));

        $discovered = [];
        $isVulnerable = false;

        // 2. 逐个 NS 尝试 TCP 53 AXFR 请求
        foreach ($nsList as $nsServer) {
            $records = $this->tryAxfrSocket($nsServer, $mainDomain);
            if (!empty($records)) {
                $isVulnerable = true;
                $discovered = array_merge($discovered, $records);
                // 成功一次即跳出
                break;
            }
        }

        return [
            'vulnerable' => $isVulnerable,
            'records'    => array_values(array_unique($discovered)),
            'ns_checked' => $nsList
        ];
    }

    /**
     * 原生 TCP 53 构造 AXFR 传送请求包
     */
    private function tryAxfrSocket(string $nsHost, string $mainDomain): array
    {
        $records = [];
        try {
            $socket = @fsockopen($nsHost, 53, $errno, $errstr, self::AXFR_TIMEOUT);
            if (!$socket) {
                return [];
            }
            stream_set_timeout($socket, self::AXFR_TIMEOUT);

            // 构造 DNS QTYPE=252 (AXFR) 请求
            $domainWire = '';
            foreach (explode('.', $mainDomain) as $part) {
                $domainWire .= chr(strlen($part)) . $part;
            }
            $domainWire .= "\x00";

            // TCP DNS 包头需要 2 字节长度前缀
            $dnsPayload = "\x12\x34" . // ID
                          "\x00\x00" . // Flags: Standard query
                          "\x00\x01" . // QDCOUNT: 1
                          "\x00\x00" . // ANCOUNT: 0
                          "\x00\x00" . // NSCOUNT: 0
                          "\x00\x00" . // ARCOUNT: 0
                          $domainWire .
                          "\x00\xFC" . // QTYPE: 252 (AXFR)
                          "\x00\x01";  // QCLASS: 1 (IN)

            $lenPrefix = pack('n', strlen($dnsPayload));
            @fwrite($socket, $lenPrefix . $dnsPayload);

            // 读取首个应答长度
            $respLenRaw = @fread($socket, 2);
            if (!$respLenRaw || strlen($respLenRaw) < 2) {
                fclose($socket);
                return [];
            }

            $respLen = unpack('n', $respLenRaw)[1];
            $response = @fread($socket, $respLen);
            fclose($socket);

            if ($response && strlen($response) > 12) {
                $flags = unpack('n', substr($response, 2, 2))[1];
                $rcode = $flags & 0x000F;
                $ancount = unpack('n', substr($response, 6, 2))[1];

                // rcode === 0 且存在 Answer 说明允许了区域传送
                if ($rcode === 0 && $ancount > 0) {
                    // 正则提取所有符合主域名格式的明文子域名
                    if (preg_match_all('/([a-zA-Z0-9.-]+\.' . preg_quote($mainDomain, '/') . ')/i', $response, $matches)) {
                        foreach ($matches[1] as $sub) {
                            $sub = strtolower(trim($sub, '. '));
                            if ($sub !== $mainDomain && filter_var($sub, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                                $records[] = $sub;
                            }
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // 静默降级
        }

        return $records;
    }
}
