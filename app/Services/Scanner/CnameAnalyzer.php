<?php

namespace App\Services\Scanner;

use App\Services\Proxy\DoHProxyClient;

class CnameAnalyzer
{
    private const MAX_DEPTH = 5;

    // 常见可接管或第三方 SaaS 托管指纹
    private array $thirdPartyProviders = [
        'github.io'           => 'GitHub Pages',
        'netlify.app'         => 'Netlify',
        'vercel.app'          => 'Vercel',
        'herokuapp.com'       => 'Heroku',
        'azurewebsites.net'   => 'Azure App Service',
        'cloudfront.net'      => 'AWS CloudFront',
        's3.amazonaws.com'    => 'AWS S3 Bucket',
        'storage.googleapis'  => 'Google Cloud Storage',
        'blob.core.windows'   => 'Azure Blob Storage',
        'fastly.net'          => 'Fastly CDN',
        'pantheonsite.io'     => 'Pantheon',
        'zendesk.com'         => 'Zendesk',
        'myshopify.com'       => 'Shopify'
    ];

    private DoHProxyClient $dohClient;

    public function __construct(DoHProxyClient $doh)
    {
        $this->dohClient = $doh;
    }

    /**
     * 递归追踪子域名 CNAME 链并分析接管风险
     */
    public function traceChain(string $subdomain, ?array $proxy = null): array
    {
        $chain = [$subdomain];
        $current = $subdomain;
        $depth = 0;
        $isDangling = false;
        $detectedProvider = null;

        while ($depth < self::MAX_DEPTH) {
            $depth++;
            $res = $this->dohClient->resolve($current, 'CNAME', $proxy);

            if (!empty($res['records'])) {
                $target = trim($res['records'][0]['data'], '. ');

                // 防自环
                if (in_array($target, $chain, true)) {
                    break;
                }

                $chain[] = $target;
                $current = $target;

                // 识别第三方服务商
                foreach ($this->thirdPartyProviders as $pattern => $provider) {
                    if (str_contains(strtolower($target), $pattern)) {
                        $detectedProvider = $provider;
                        break;
                    }
                }
            } else {
                // 不再有 CNAME，检查最后一跳是否能解析出 A 记录
                $resA = $this->dohClient->resolve($current, 'A', $proxy);
                if (empty($resA['records']) && count($chain) > 1) {
                    // 悬挂 CNAME：链指向了无法解析的目标，存在潜在子域名接管风险！
                    $isDangling = true;
                }
                break;
            }
        }

        return [
            'chain'         => $chain,
            'is_dangling'   => $isDangling,
            'is_takeover'   => $isDangling && !empty($detectedProvider),
            'provider'      => $detectedProvider,
            'reason'        => $isDangling ? ($detectedProvider ? "悬挂至 {$detectedProvider}，存在子域名接管风险" : "CNAME 最后一跳解析失效") : null
        ];
    }
}
