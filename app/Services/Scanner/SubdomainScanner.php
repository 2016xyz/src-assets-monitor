<?php

namespace App\Services\Scanner;

use App\Core\App;
use App\Core\Database;
use App\Services\Proxy\DoHProxyClient;
use App\Services\Proxy\ProxyScheduler;

class SubdomainScanner
{
    private DoHProxyClient $dohClient;
    private ProxyScheduler $scheduler;
    private AssetNameResolver $nameResolver;
    private PassiveCollectorPool $passivePool;
    private WildcardDetector $wildcardDetector;
    private CnameAnalyzer $cnameAnalyzer;
    private ZoneTransferScanner $axfrScanner;
    private BucketTakeoverDetector $bucketDetector;
    private GitHubDorkScanner $githubScanner;
    private JsSourceMapExtractor $jsExtractor;

    public function __construct(DoHProxyClient $doh, ProxyScheduler $scheduler)
    {
        $this->dohClient = $doh;
        $this->scheduler = $scheduler;
        $this->nameResolver = new AssetNameResolver();
        $this->passivePool = new PassiveCollectorPool();
        $this->wildcardDetector = new WildcardDetector($doh);
        $this->cnameAnalyzer = new CnameAnalyzer($doh);
        $this->axfrScanner = new ZoneTransferScanner($doh);
        $this->bucketDetector = new BucketTakeoverDetector();
        $this->githubScanner = new GitHubDorkScanner();
        $this->jsExtractor = new JsSourceMapExtractor();
    }

    /**
     * 执行全流程子域名检测 (支持轻量被动轮询 vs 每日一次深度字典爆破)
     *
     * @param array $domain 目标主域名数据行
     * @param int $taskId 任务ID
     * @param bool $forceBrute 是否执行主动深度大字典爆破 (默认每天自动触发一次)
     */
    public function scan(array $domain, int $taskId, bool $forceBrute = false): array
    {
        $this->logTask($taskId, 'passive_multi', 'info', "开始对 [{$domain['domain']}] 执行全景资产多轨深度探测");

        // 1. 确定出口代理
        $proxy = null;
        if ($domain['proxy_mode'] === 'proxy_group' && !empty($domain['proxy_group_id'])) {
            $proxy = $this->scheduler->selectProxy((int)$domain['proxy_group_id'], $domain['domain']);
        }

        $candidatesPool = []; // [subdomain => ['sources' => [...]]]

        // 2. 阶段一：多源被动并发采集 (SubdomainCenter / crt.sh / RapidDNS / CertSpotter / ThreatMiner / TLS-SAN...)
        $this->logTask($taskId, 'passive_multi', 'info', "正在并发查询多轨被动数据源与权威 DNS 记录");
        $passiveResults = $this->passivePool->collectAll($domain['domain'], $proxy);
        foreach ($passiveResults as $sub => $meta) {
            $candidatesPool[$sub] = $meta;
        }
        $this->logTask($taskId, 'passive_multi', 'info', "被动多源聚合提取到 " . count($passiveResults) . " 个唯一候选子域名");

        // 3. 阶段二：AXFR 区域传送 (显式开启时探测)
        if (!empty($domain['enable_axfr'])) {
            $this->logTask($taskId, 'axfr_probe', 'info', "执行 DNS 区域传送 (AXFR) 弱点探测");
            $axfrRes = $this->axfrScanner->probeAxfr($domain['domain'], $proxy);
            if ($axfrRes['vulnerable']) {
                $this->logTask($taskId, 'axfr_probe', 'warn', "权威 DNS 存在区域传送漏洞！单次提取 " . count($axfrRes['records']) . " 个记录");
                foreach ($axfrRes['records'] as $sub) {
                    $this->appendCandidate($candidatesPool, $sub, 'axfr');
                }
            }
        }

        // 4. 阶段三：GitHub Dorks 代码泄露资产搜寻
        $this->logTask($taskId, 'github_dork', 'info', "执行 GitHub Dorks 代码泄露资产搜寻");
        $githubSubs = $this->githubScanner->search($domain['domain'], $proxy);
        foreach ($githubSubs as $sub) {
            $this->appendCandidate($candidatesPool, $sub, 'github_dork');
        }

        // 5. 阶段四：泛解析检测 (Wildcard DNS)
        $wildcardInfo = ['has_wildcard' => false];
        if (!empty($domain['enable_wildcard_filter'])) {
            $this->logTask($taskId, 'wildcard_check', 'info', "正在探测目标主域名泛解析 (Wildcard) 特征");
            $wildcardInfo = $this->wildcardDetector->detect($domain['domain'], $proxy);
            if ($wildcardInfo['has_wildcard']) {
                $this->logTask($taskId, 'wildcard_check', 'warn', "检测到目标主域存在泛解析！已捕获过滤特征: " . implode(', ', array_merge($wildcardInfo['wildcard_ips'], $wildcardInfo['wildcard_cnames'])));
            }
        }

        // 6. 阶段五：定时每日深度超大字典爆破 (2500+ 精华词汇 + 智能衍生)
        $lastBrute = !empty($domain['last_brute_at']) ? strtotime($domain['last_brute_at']) : 0;
        $isBruteTime = $forceBrute || (time() - $lastBrute >= 86400) || empty($domain['last_brute_at']);

        if ($isBruteTime) {
            $dict = $this->generatePermutationDictionary($domain['domain'], array_keys($candidatesPool));
            $dictCount = count($dict);
            $this->logTask($taskId, 'brute_enum', 'info', "【每日定时大字典爆破】调度包含 {$dictCount} 个精华高频词与前缀衍生进行全网暴力探测");
            foreach ($dict as $w) {
                $sub = "{$w}.{$domain['domain']}";
                $this->appendCandidate($candidatesPool, $sub, 'brute_enum');
            }
            Database::update('domains', ['last_brute_at' => date('Y-m-d H:i:s')], 'id = ?', [$domain['id']]);
        } else {
            $nextHours = round((86400 - (time() - $lastBrute)) / 3600, 1);
            $this->logTask($taskId, 'brute_enum', 'info', "今日大字典全量爆破已完成，本轮执行高速存活核查 (距下次全量爆破约 {$nextHours} 小时)");
        }

        $totalCandidates = count($candidatesPool);
        $this->logTask($taskId, 'brute_dns', 'info', "全源候选池汇总就绪，共计 {$totalCandidates} 个，启动 40 路并发 DoH 并行解析");

        // 7. 高性能并发批量 DoH 解析 (按 subdomain 维度整合 A 与 CNAME)
        $resolvedMap = [];
        $candidateKeys = array_keys($candidatesPool);
        $chunks = array_chunk($candidateKeys, 30);

        foreach ($chunks as $chunk) {
            $queries = [];
            foreach ($chunk as $sub) {
                $queries[] = ['subdomain' => $sub, 'type' => 'A'];
                $queries[] = ['subdomain' => $sub, 'type' => 'CNAME'];
            }

            $batchResults = $this->dohClient->resolveParallel($queries, $proxy);

            foreach ($batchResults as $queryKey => $answers) {
                if (!empty($answers)) {
                    [$sub, $queryType] = explode(':', $queryKey);
                    if (!isset($resolvedMap[$sub])) {
                        $resolvedMap[$sub] = [
                            'subdomain' => $sub,
                            'ips'       => [],
                            'cname'     => null,
                            'ttl'       => 300,
                            'sources'   => $candidatesPool[$sub]['sources'] ?? ['unknown']
                        ];
                    }

                    foreach ($answers as $r) {
                        $val = trim($r['data'], '. ');

                        // 泛解析命中过滤
                        if ($wildcardInfo['has_wildcard'] && $this->wildcardDetector->isWildcardMatch($val, $wildcardInfo)) {
                            continue;
                        }

                        if ($r['type'] === 'CNAME') {
                            $resolvedMap[$sub]['cname'] = $val;
                        } elseif ($r['type'] === 'A' && filter_var($val, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                            if (!in_array($val, $resolvedMap[$sub]['ips'], true)) {
                                $resolvedMap[$sub]['ips'][] = $val;
                            }
                        }
                    }
                }
            }
            usleep(50000);
        }

        // 8. 过滤掉仅命中泛解析被清空的假子域，整理出存活列表
        $activeEntries = [];
        foreach ($resolvedMap as $sub => $info) {
            if (!empty($info['ips']) || !empty($info['cname'])) {
                $activeEntries[$sub] = $info;
            }
        }

        // 9. 阶段六：CNAME 链追踪与云存储桶接管检测
        $this->logTask($taskId, 'cname_takeover', 'info', "分析 CNAME 链与云存储/SaaS 悬挂接管风险");
        $analyzedEntries = $this->enrichCnameAndTakeoverEntries($activeEntries, $proxy);

        // 10. 阶段七：存活 Web 资产深入提取 JS 与 Source Map
        $this->logTask($taskId, 'js_crawl', 'info', "存活 Web 资产提取 JavaScript 与 Source Map 深度挖掘");
        $jsDiscovered = $this->extractFromWebAssetsEntries($analyzedEntries, $domain['domain'], $proxy);
        if (!empty($jsDiscovered)) {
            $this->logTask($taskId, 'js_crawl', 'info', "JS 深度挖掘出额外 " . count($jsDiscovered) . " 个端点");
            foreach ($jsDiscovered as $jsSub) {
                if (!isset($analyzedEntries[$jsSub])) {
                    $res = $this->dohClient->resolve($jsSub, 'A', $proxy);
                    if (!empty($res['records'])) {
                        $ips = [];
                        $cname = null;
                        foreach ($res['records'] as $r) {
                            if ($r['type'] === 'A') $ips[] = trim($r['data'], '. ');
                            if ($r['type'] === 'CNAME') $cname = trim($r['data'], '. ');
                        }
                        if (!empty($ips) || $cname) {
                            $analyzedEntries[$jsSub] = [
                                'subdomain'       => $jsSub,
                                'ips'             => $ips,
                                'cname'           => $cname,
                                'ttl'             => 300,
                                'sources'         => ['js_sourcemap'],
                                'takeover_risk'   => 0,
                                'takeover_reason' => null,
                                'cname_chain'     => null
                            ];
                        }
                    }
                }
            }
        }

        // 11. 阶段八：识别被动证书源中存在、但当前 DNS 未解析的历史资产 (保证全景资产 100% 入库)
        $historicalInactive = [];
        foreach ($candidatesPool as $candSub => $candMeta) {
            if (!isset($analyzedEntries[$candSub])) {
                $isPassive = false;
                foreach ($candMeta['sources'] as $src) {
                    if (in_array($src, ['crt.sh', 'subdomain_center', 'certspotter', 'hackertarget', 'rapiddns', 'wayback_archive', 'threatminer', 'dns_zone', 'tls_san'], true)) {
                        $isPassive = true;
                        break;
                    }
                }
                if ($isPassive) {
                    $historicalInactive[$candSub] = [
                        'subdomain'   => $candSub,
                        'sources'     => $candMeta['sources']
                    ];
                }
            }
        }

        $this->logTask($taskId, 'snapshot_diff', 'info', "单子域名唯一聚合比对 (存活子域 " . count($analyzedEntries) . " 个，历史证书子域 " . count($historicalInactive) . " 个)");
        $changes = $this->diffAndPersistUnified($domain, $taskId, $analyzedEntries, $historicalInactive, $proxy);

        return [
            'total_active'     => count($analyzedEntries),
            'total_historical' => count($historicalInactive),
            'changes'          => $changes
        ];
    }

    /**
     * 生成超大复合精华字典 (加载 database/dictionary.txt 文件字典 + 智能拼音/数字/多级变异衍生)
     */
    private function generatePermutationDictionary(string $mainDomain, array $existingCandidates = []): array
    {
        $dictFile = App::basePath('database/dictionary.txt');
        $fileWords = [];
        if (file_exists($dictFile)) {
            $lines = file($dictFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($lines)) {
                foreach ($lines as $line) {
                    $w = strtolower(trim($line));
                    if ($w !== '' && !str_starts_with($w, '#')) {
                        $fileWords[] = $w;
                    }
                }
            }
        }

        // 兜底常用核心服务词汇
        $coreWords = [
            'www', 'api', 'mail', 'admin', 'app', 'm', 'h5', 'wap', 'test', 'dev', 'uat', 'stg', 'prod',
            'vpn', 'oa', 'git', 'auth', 'login', 'sso', 'cas', 'pay', 'shop', 'mall', 'bbs', 'forum',
            'gateway', 'proxy', 'ngrok', 'frp', 'ssh', 'rdp', 'k8s', 'docker', 'pve', 'nacos', 'apollo',
            'redis', 'mysql', 'sql', 'db', 'minio', 'oss', 'cos', 'kafka', 'mq', 'monitor', 'zabbix',
            'grafana', 'elk', 'sec', 'waf', 'nmap', 'new', 'ai', 'bx', 'wx', 'st', 'sh', 'cp', 'sp'
        ];

        // 用户在设置中自定义的子域名字典
        $customDict = [];
        $row = Database::fetchOne("SELECT `value` FROM `settings` WHERE `key` = 'dictionary_subdomains'");
        if ($row && !empty($row['value'])) {
            $parsed = json_decode($row['value'], true);
            if (is_array($parsed)) $customDict = $parsed;
        }

        $allWords = array_values(array_unique(array_merge($fileWords, $coreWords, $customDict)));

        // 环境变体衍生 (针对前 40 个最核心高频业务词汇生成 -dev, -test, -stg, -uat, -prod 等)
        $environments = ['dev', 'test', 'uat', 'stg', 'prod', 'inner', 'internal'];
        $generated = $allWords;

        foreach (array_slice($allWords, 0, 40) as $word) {
            foreach ($environments as $env) {
                $generated[] = "{$word}-{$env}";
                $generated[] = "{$env}-{$word}";
            }
            $generated[] = "{$word}1";
            $generated[] = "{$word}2";
        }

        // 多级子域衍生 (如针对 cp 生成 api.cp, ap.cp, admin.cp, m.cp)
        foreach ($existingCandidates as $cand) {
            $parts = explode('.', $cand);
            if (count($parts) >= 3) {
                $subPrefix = $parts[0];
                foreach (['api', 'ap', 'admin', 'test', 'dev', 'wap', 'm'] as $p) {
                    $generated[] = "{$p}.{$subPrefix}";
                }
            }
        }

        return array_values(array_unique($generated));
    }

    private function enrichCnameAndTakeoverEntries(array $entries, ?array $proxy): array
    {
        foreach ($entries as $sub => &$rec) {
            $rec['takeover_risk'] = 0;
            $rec['takeover_reason'] = null;
            $rec['cname_chain'] = null;

            if (!empty($rec['cname'])) {
                $trace = $this->cnameAnalyzer->traceChain($sub, $proxy);
                $rec['cname_chain'] = json_encode($trace['chain'], JSON_UNESCAPED_SLASHES);

                if (!empty($trace['is_takeover'])) {
                    $rec['takeover_risk'] = 1;
                    $rec['takeover_reason'] = $trace['reason'];
                } else {
                    $bucketCheck = $this->bucketDetector->checkBucketStatus($rec['cname'], $proxy);
                    if ($bucketCheck['is_dangling_bucket']) {
                        $rec['takeover_risk'] = 1;
                        $rec['takeover_reason'] = $bucketCheck['reason'];
                    }
                }
            }
        }
        return $entries;
    }

    private function extractFromWebAssetsEntries(array $entries, string $mainDomain, ?array $proxy): array
    {
        $discovered = [];
        $tested = 0;

        foreach ($entries as $sub => $r) {
            if ($tested >= 4) break;
            if (!empty($r['ips'])) {
                $url = "https://{$sub}/";
                $subs = $this->jsExtractor->extractFromWeb($url, $mainDomain, $proxy);
                $discovered = array_merge($discovered, $subs);
                $tested++;
            }
        }
        return array_values(array_unique($discovered));
    }

    /**
     * 单子域名唯一归一化持久化与比对 (彻底消除 A/CNAME 重复展示，支持良性 CDN 漂移平滑与告警)
     */
    private function diffAndPersistUnified(array $domain, int $taskId, array $activeEntries, array $inactiveCandidates, ?array $proxy): array
    {
        $existing = Database::fetchAll("SELECT * FROM subdomains WHERE domain_id = ?", [$domain['id']]);
        $existingMap = [];
        foreach ($existing as $ex) {
            $existingMap[$ex['subdomain']] = $ex;
        }

        $changes = [];

        foreach ($activeEntries as $sub => $info) {
            $primarySource = ($info['sources'][0] ?? 'unknown');
            $priority = $this->calculatePriority($primarySource, !empty($info['takeover_risk']));

            $displayValue = !empty($info['ips']) ? implode(', ', $info['ips']) : $info['cname'];
            $cnameRecord = $info['cname'] ?? null;
            $recordType = !empty($info['ips']) ? 'A' : 'CNAME';

            if (!isset($existingMap[$sub])) {
                $nameInfo = $this->nameResolver->resolve(
                    $sub,
                    $domain['domain'],
                    $recordType,
                    $displayValue,
                    null,
                    $proxy
                );

                $changes[] = [
                    'domain_id'         => $domain['id'],
                    'subdomain'         => $sub,
                    'asset_name'        => $nameInfo['asset_name'],
                    'asset_name_source' => $nameInfo['asset_name_source'],
                    'provenance_source' => $primarySource,
                    'priority_level'    => $priority,
                    'record_type'       => $recordType,
                    'change_type'       => 'added',
                    'old_value'         => null,
                    'new_value'         => $displayValue . ($cnameRecord ? " (CNAME: {$cnameRecord})" : "")
                ];

                $newSubId = Database::insert('subdomains', [
                    'domain_id'             => $domain['id'],
                    'subdomain'             => $sub,
                    'asset_name'            => $nameInfo['asset_name'],
                    'alias_name'            => null,
                    'asset_name_source'     => $nameInfo['asset_name_source'],
                    'asset_name_updated_at' => $nameInfo['asset_name_updated_at'],
                    'record_type'           => $recordType,
                    'record_value'          => $displayValue,
                    'cname_record'          => $cnameRecord,
                    'source'                => $primarySource,
                    'status'                => 'active',
                    'missing_count'         => 0,
                    'takeover_risk'         => $info['takeover_risk'] ?? 0,
                    'takeover_reason'       => $info['takeover_reason'] ?? null,
                    'cname_chain'           => $info['cname_chain'] ?? null,
                    'provenance_sources'    => json_encode($info['sources'], JSON_UNESCAPED_UNICODE),
                    'first_seen_at'         => date('Y-m-d H:i:s'),
                    'last_seen_at'          => date('Y-m-d H:i:s'),
                    'created_at'            => date('Y-m-d H:i:s')
                ]);

                $existingMap[$sub] = [
                    'id'            => $newSubId,
                    'record_value'  => $displayValue,
                    'cname_record'  => $cnameRecord,
                    'status'        => 'active',
                    'missing_count' => 0
                ];
            } else {
                $old = $existingMap[$sub];

                if ($old['status'] !== 'active' || ($old['missing_count'] ?? 0) > 0) {
                    Database::update('subdomains', [
                        'status'        => 'active',
                        'missing_count' => 0,
                        'last_seen_at'  => date('Y-m-d H:i:s')
                    ], 'id = ?', [$old['id']]);
                }

                $isValChanged = ($old['record_value'] !== $displayValue);
                $isCnameChanged = (($old['cname_record'] ?? '') !== ($cnameRecord ?? ''));

                if ($isValChanged || $isCnameChanged) {
                    $isCdnManaged = (!empty($cnameRecord) && CdnDriftFilter::isCdnCname($cnameRecord)) ||
                                    (!empty($old['cname_record']) && CdnDriftFilter::isCdnCname($old['cname_record']));

                    $isBenign = false;
                    if (!$isCnameChanged && $isValChanged) {
                        $isBenign = CdnDriftFilter::isBenignCdnDrift(
                            $old['record_value'],
                            $displayValue,
                            $isCdnManaged,
                            $info['cname_chain'] ?? ($old['cname_chain'] ?? null)
                        );
                    }

                    if ($isBenign) {
                        Database::update('subdomains', [
                            'record_value' => $displayValue,
                            'cname_record' => $cnameRecord,
                            'last_seen_at' => date('Y-m-d H:i:s')
                        ], 'id = ?', [$old['id']]);
                    } else {
                        $nameInfo = $this->nameResolver->resolve(
                            $sub,
                            $domain['domain'],
                            $recordType,
                            $displayValue,
                            $old['alias_name'] ?? null,
                            $proxy
                        );

                        $changes[] = [
                            'domain_id'         => $domain['id'],
                            'subdomain'         => $sub,
                            'asset_name'        => $nameInfo['asset_name'],
                            'asset_name_source' => $nameInfo['asset_name_source'],
                            'provenance_source' => $primarySource,
                            'priority_level'    => $priority,
                            'record_type'       => $recordType,
                            'change_type'       => 'changed',
                            'old_value'         => $old['record_value'],
                            'new_value'         => $displayValue . ($cnameRecord ? " (CNAME: {$cnameRecord})" : "")
                        ];

                        Database::update('subdomains', [
                            'asset_name'            => $nameInfo['asset_name'],
                            'asset_name_source'     => $nameInfo['asset_name_source'],
                            'asset_name_updated_at' => $nameInfo['asset_name_updated_at'],
                            'record_type'           => $recordType,
                            'record_value'          => $displayValue,
                            'cname_record'          => $cnameRecord,
                            'takeover_risk'         => $info['takeover_risk'] ?? 0,
                            'takeover_reason'       => $info['takeover_reason'] ?? null,
                            'cname_chain'           => $info['cname_chain'] ?? null,
                            'status'                => 'active',
                            'missing_count'         => 0,
                            'last_seen_at'          => date('Y-m-d H:i:s')
                        ], 'id = ?', [$old['id']]);
                    }
                } else {
                    Database::update('subdomains', [
                        'last_seen_at'    => date('Y-m-d H:i:s'),
                        'takeover_risk'   => $info['takeover_risk'] ?? 0,
                        'takeover_reason' => $info['takeover_reason'] ?? null
                    ], 'id = ?', [$old['id']]);
                }
            }
        }

        foreach ($inactiveCandidates as $candSub => $candMeta) {
            if (isset($existingMap[$candSub])) {
                continue;
            }

            $primarySource = ($candMeta['sources'][0] ?? 'crt.sh') . ' (历史证书)';
            Database::insert('subdomains', [
                'domain_id'             => $domain['id'],
                'subdomain'             => $candSub,
                'asset_name'            => $candSub,
                'alias_name'            => null,
                'asset_name_source'     => 'hostname',
                'asset_name_updated_at' => null,
                'record_type'           => 'A',
                'record_value'          => '未配置公网解析 (历史证书源)',
                'cname_record'          => null,
                'source'                => $primarySource,
                'status'                => 'nxdomain',
                'missing_count'         => 0,
                'takeover_risk'         => 0,
                'takeover_reason'       => null,
                'cname_chain'           => null,
                'provenance_sources'    => json_encode($candMeta['sources'], JSON_UNESCAPED_UNICODE),
                'first_seen_at'         => date('Y-m-d H:i:s'),
                'last_seen_at'          => date('Y-m-d H:i:s'),
                'created_at'            => date('Y-m-d H:i:s')
            ]);
            $existingMap[$candSub] = true;
        }

        foreach ($existingMap as $candSub => $old) {
            if (is_array($old) && !isset($activeEntries[$candSub]) && $old['status'] === 'active') {
                $retryRes = $this->dohClient->resolve($candSub, $old['record_type'] ?? 'A', $proxy);
                if (!empty($retryRes['records'])) {
                    Database::update('subdomains', [
                        'last_seen_at'  => date('Y-m-d H:i:s'),
                        'missing_count' => 0
                    ], 'id = ?', [$old['id']]);
                    continue;
                }

                $curMissing = (int)($old['missing_count'] ?? 0) + 1;
                if ($curMissing < 3) {
                    Database::update('subdomains', ['missing_count' => $curMissing], 'id = ?', [$old['id']]);
                } else {
                    $changes[] = [
                        'domain_id'         => $domain['id'],
                        'subdomain'         => $candSub,
                        'asset_name'        => $old['asset_name'] ?: $candSub,
                        'asset_name_source' => $old['asset_name_source'] ?: 'hostname',
                        'provenance_source' => 'snapshot_diff',
                        'priority_level'    => 'normal',
                        'record_type'       => $old['record_type'] ?? 'A',
                        'change_type'       => 'removed',
                        'old_value'         => $old['record_value'],
                        'new_value'         => null
                    ];

                    Database::update('subdomains', [
                        'status'        => 'nxdomain',
                        'missing_count' => $curMissing
                    ], 'id = ?', [$old['id']]);
                }
            }
        }

        foreach ($changes as $c) {
            Database::insert('change_logs', array_merge($c, ['created_at' => date('Y-m-d H:i:s')]));
        }

        $snapshotJson = json_encode($activeEntries, JSON_UNESCAPED_UNICODE);
        Database::insert('dns_snapshots', [
            'domain_id'     => $domain['id'],
            'task_id'       => $taskId,
            'snapshot_hash' => hash('sha256', $snapshotJson),
            'total_records' => count($activeEntries),
            'snapshot_data' => $snapshotJson,
            'created_at'    => date('Y-m-d H:i:s')
        ]);

        $totalSubCount = Database::count('subdomains', 'domain_id = ?', [$domain['id']]);
        Database::update('domains', [
            'subdomain_count' => $totalSubCount,
            'last_scanned_at' => date('Y-m-d H:i:s')
        ], 'id = ?', [$domain['id']]);

        return $changes;
    }

    private function calculatePriority(string $source, bool $isTakeover): string
    {
        if ($isTakeover) return 'critical';
        if (in_array($source, ['crt.sh', 'subdomain_center', 'certspotter', 'tls_san'], true)) return 'high';
        if (in_array($source, ['brute_enum', 'axfr'], true)) return 'high';
        return 'normal';
    }

    private function appendCandidate(array &$pool, string $sub, string $source): void
    {
        $sub = strtolower(trim($sub, '. '));
        if ($sub === '' || !filter_var($sub, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return;
        }
        if (!isset($pool[$sub])) {
            $pool[$sub] = ['sources' => [$source]];
        } elseif (!in_array($source, $pool[$sub]['sources'], true)) {
            $pool[$sub]['sources'][] = $source;
        }
    }

    private function logTask(int $taskId, string $stage, string $level, string $msg): void
    {
        Database::insert('scan_task_logs', [
            'task_id'    => $taskId,
            'stage'      => $stage,
            'level'      => $level,
            'message'    => $msg,
            'created_at' => date('Y-m-d H:i:s')
        ]);
    }
}
