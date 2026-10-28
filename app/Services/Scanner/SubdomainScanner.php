<?php

namespace App\Services\Scanner;

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

    public function scan(array $domain, int $taskId): array
    {
        $this->logTask($taskId, 'passive_multi', 'info', "开始对 [{$domain['domain']}] 执行全景资产多源探测");

        // 1. 确定出口代理
        $proxy = null;
        if ($domain['proxy_mode'] === 'proxy_group' && !empty($domain['proxy_group_id'])) {
            $proxy = $this->scheduler->selectProxy((int)$domain['proxy_group_id'], $domain['domain']);
        }

        $candidatesPool = []; // [subdomain => ['sources' => [...]]]

        // 2. 阶段一：多源被动并发采集 (8+ 源)
        $this->logTask($taskId, 'passive_multi', 'info', "正在并发查询 8+ 被动数据源 (crt.sh/CertSpotter/OTX/Wayback/TLS-SAN...)");
        $passiveResults = $this->passivePool->collectAll($domain['domain'], $proxy);
        foreach ($passiveResults as $sub => $meta) {
            $candidatesPool[$sub] = $meta;
        }
        $this->logTask($taskId, 'passive_multi', 'info', "被动多源聚合提取到 " . count($passiveResults) . " 个唯一候选子域名");

        // 3. 阶段二：AXFR 区域传送 (仅显式开启时执行)
        if (!empty($domain['enable_axfr'])) {
            $this->logTask($taskId, 'axfr_probe', 'info', "执行 DNS 区域传送 (AXFR) 弱点探测");
            $axfrRes = $this->axfrScanner->probeAxfr($domain['domain'], $proxy);
            if ($axfrRes['vulnerable']) {
                $this->logTask($taskId, 'axfr_probe', 'warn', "目标权威 DNS 存在区域传送漏洞！单次提取 " . count($axfrRes['records']) . " 个记录");
                foreach ($axfrRes['records'] as $sub) {
                    $this->appendCandidate($candidatesPool, $sub, 'axfr');
                }
            }
        }

        // 4. 阶段三：GitHub Dorks 代码泄露搜寻
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

        // 6. 阶段五：字典置换生成与并发解析验证
        $dict = $this->generatePermutationDictionary($domain['domain']);
        foreach ($dict as $w) {
            $sub = "{$w}.{$domain['domain']}";
            $this->appendCandidate($candidatesPool, $sub, 'brute_enum');
        }

        $this->logTask($taskId, 'brute_dns', 'info', "全源候选池汇总就绪，共计 " . count($candidatesPool) . " 个，开始执行并发 DoH 解析与泛解析清洗");

        $activeRecords = [];
        $batches = array_chunk(array_keys($candidatesPool), 20);

        foreach ($batches as $batch) {
            foreach ($batch as $sub) {
                foreach (['A', 'CNAME'] as $type) {
                    $res = $this->dohClient->resolve($sub, $type, $proxy);
                    if (!empty($res['records'])) {
                        foreach ($res['records'] as $r) {
                            $val = trim($r['data'], '. ');

                            // 泛解析命中过滤
                            if ($wildcardInfo['has_wildcard'] && $this->wildcardDetector->isWildcardMatch($val, $wildcardInfo)) {
                                continue;
                            }

                            $activeRecords[] = [
                                'subdomain'   => $sub,
                                'record_type' => $r['type'],
                                'value'       => $val,
                                'ttl'         => $r['ttl'],
                                'sources'     => $candidatesPool[$sub]['sources'] ?? ['unknown']
                            ];
                        }
                    }
                }
            }
            usleep(mt_rand(150000, 300000));
        }

        // 7. 阶段六：CNAME 链追踪与云存储桶接管检测
        $this->logTask($taskId, 'cname_takeover', 'info', "正在分析 CNAME 链与云存储/SaaS 悬挂接管风险");
        $analyzedRecords = $this->enrichCnameAndTakeover($activeRecords, $proxy);

        // 8. 阶段七：对存活 Web 资产挖掘 JavaScript 与 Source Map
        $this->logTask($taskId, 'js_crawl', 'info', "对存活 Web 资产提取 JavaScript 与 Source Map 深度挖掘");
        $jsDiscovered = $this->extractFromWebAssets($analyzedRecords, $domain['domain'], $proxy);
        if (!empty($jsDiscovered)) {
            $this->logTask($taskId, 'js_crawl', 'info', "JS 深度挖掘出额外 " . count($jsDiscovered) . " 个潜在内部端点");
            foreach ($jsDiscovered as $jsSub) {
                $res = $this->dohClient->resolve($jsSub, 'A', $proxy);
                if (!empty($res['records'])) {
                    $analyzedRecords[] = [
                        'subdomain'       => $jsSub,
                        'record_type'     => 'A',
                        'value'           => $res['records'][0]['data'],
                        'ttl'             => 300,
                        'sources'         => ['js_sourcemap'],
                        'takeover_risk'   => 0,
                        'takeover_reason' => null,
                        'cname_chain'     => null
                    ];
                }
            }
        }

        // 9. 阶段八：快照比对、CDN Anycast 漂移平滑过滤、NXDOMAIN 防抖与资产名称识别
        $this->logTask($taskId, 'snapshot_diff', 'info', "执行快照比对与 CDN Anycast 漂移防误报平滑过滤");
        $changes = $this->diffAndPersistExtended($domain, $taskId, $analyzedRecords, $proxy);

        return [
            'total_active' => count($analyzedRecords),
            'changes'      => $changes
        ];
    }

    private function generatePermutationDictionary(string $mainDomain): array
    {
        $baseDict = ['www', 'mail', 'api', 'admin', 'test', 'dev', 'vpn', 'oa', 'git', 'jenkins', 'auth', 'portal'];
        $row = Database::fetchOne("SELECT `value` FROM `settings` WHERE `key` = 'dictionary_subdomains'");
        if ($row && !empty($row['value'])) {
            $parsed = json_decode($row['value'], true);
            if (is_array($parsed)) $baseDict = $parsed;
        }

        $environments = ['dev', 'test', 'uat', 'stg', 'prod', 'inner', 'corp'];
        $generated = $baseDict;

        foreach (array_slice($baseDict, 0, 15) as $word) {
            foreach ($environments as $env) {
                $generated[] = "{$word}-{$env}";
                $generated[] = "{$env}-{$word}";
            }
            $generated[] = "{$word}1";
            $generated[] = "{$word}2";
        }

        return array_values(array_unique($generated));
    }

    private function enrichCnameAndTakeover(array $records, ?array $proxy): array
    {
        foreach ($records as &$rec) {
            $rec['takeover_risk'] = 0;
            $rec['takeover_reason'] = null;
            $rec['cname_chain'] = null;

            if ($rec['record_type'] === 'CNAME') {
                $trace = $this->cnameAnalyzer->traceChain($rec['subdomain'], $proxy);
                $rec['cname_chain'] = json_encode($trace['chain'], JSON_UNESCAPED_SLASHES);

                if (!empty($trace['is_takeover'])) {
                    $rec['takeover_risk'] = 1;
                    $rec['takeover_reason'] = $trace['reason'];
                } else {
                    $bucketCheck = $this->bucketDetector->checkBucketStatus($rec['value'], $proxy);
                    if ($bucketCheck['is_dangling_bucket']) {
                        $rec['takeover_risk'] = 1;
                        $rec['takeover_reason'] = $bucketCheck['reason'];
                    }
                }
            }
        }
        return $records;
    }

    private function extractFromWebAssets(array $records, string $mainDomain, ?array $proxy): array
    {
        $discovered = [];
        $tested = 0;

        foreach ($records as $r) {
            if ($tested >= 3) break;
            if ($r['record_type'] === 'A') {
                $url = "https://{$r['subdomain']}/";
                $subs = $this->jsExtractor->extractFromWeb($url, $mainDomain, $proxy);
                $discovered = array_merge($discovered, $subs);
                $tested++;
            }
        }
        return array_values(array_unique($discovered));
    }

    /**
     * 核心比对与落库逻辑（内置 CDN Anycast 漂移平滑过滤 + NXDOMAIN 防抖重测）
     */
    private function diffAndPersistExtended(array $domain, int $taskId, array $records, ?array $proxy): array
    {
        // 1. 本次候选集按 subdomain + record_type 唯一化去重
        $dedupRecords = [];
        foreach ($records as $r) {
            $dedupKey = "{$r['subdomain']}:{$r['record_type']}";
            $dedupRecords[$dedupKey] = $r;
        }
        $records = array_values($dedupRecords);

        // 2. 载入历史记录
        $existing = Database::fetchAll("SELECT * FROM subdomains WHERE domain_id = ?", [$domain['id']]);
        $existingMap = [];
        foreach ($existing as $ex) {
            $existingMap["{$ex['subdomain']}:{$ex['record_type']}"] = $ex;
        }

        // 关键增强 1: 扫描全量记录，构建 CDN 托管的子域名白名单集合
        $cdnManagedSubs = [];
        foreach ($records as $r) {
            if ($r['record_type'] === 'CNAME' && (CdnDriftFilter::isCdnCname($r['value']) || CdnDriftFilter::isCdnCname($r['cname_chain'] ?? ''))) {
                $cdnManagedSubs[$r['subdomain']] = true;
            }
        }
        foreach ($existing as $ex) {
            if ($ex['record_type'] === 'CNAME' && (CdnDriftFilter::isCdnCname($ex['record_value']) || CdnDriftFilter::isCdnCname($ex['cname_chain'] ?? ''))) {
                $cdnManagedSubs[$ex['subdomain']] = true;
            }
        }

        $currentMap = [];
        $changes = [];

        // 3. 处理新增与变更比对
        foreach ($records as $r) {
            $key = "{$r['subdomain']}:{$r['record_type']}";
            $currentMap[$key] = $r;
            $sourcesJson = json_encode($r['sources'] ?? ['unknown'], JSON_UNESCAPED_UNICODE);
            $primarySource = ($r['sources'][0] ?? 'unknown');
            $priority = $this->calculatePriority($primarySource, !empty($r['takeover_risk']));

            if (!isset($existingMap[$key])) {
                // 真正的全新资产发现
                $nameInfo = $this->nameResolver->resolve(
                    $r['subdomain'],
                    $domain['domain'],
                    $r['record_type'],
                    $r['value'],
                    null,
                    $proxy
                );

                $changes[] = [
                    'domain_id'         => $domain['id'],
                    'subdomain'         => $r['subdomain'],
                    'asset_name'        => $nameInfo['asset_name'],
                    'asset_name_source' => $nameInfo['asset_name_source'],
                    'provenance_source' => $primarySource,
                    'priority_level'    => $priority,
                    'record_type'       => $r['record_type'],
                    'change_type'       => 'added',
                    'old_value'         => null,
                    'new_value'         => $r['value']
                ];

                $newSubId = Database::insert('subdomains', [
                    'domain_id'             => $domain['id'],
                    'subdomain'             => $r['subdomain'],
                    'asset_name'            => $nameInfo['asset_name'],
                    'alias_name'            => null,
                    'asset_name_source'     => $nameInfo['asset_name_source'],
                    'asset_name_updated_at' => $nameInfo['asset_name_updated_at'],
                    'record_type'           => $r['record_type'],
                    'record_value'          => $r['value'],
                    'source'                => $primarySource,
                    'status'                => 'active',
                    'missing_count'         => 0,
                    'takeover_risk'         => $r['takeover_risk'] ?? 0,
                    'takeover_reason'       => $r['takeover_reason'] ?? null,
                    'cname_chain'           => $r['cname_chain'] ?? null,
                    'provenance_sources'    => $sourcesJson,
                    'first_seen_at'         => date('Y-m-d H:i:s'),
                    'last_seen_at'          => date('Y-m-d H:i:s'),
                    'created_at'            => date('Y-m-d H:i:s')
                ]);

                $existingMap[$key] = [
                    'id'            => $newSubId,
                    'record_value'  => $r['value'],
                    'status'        => 'active',
                    'missing_count' => 0,
                    'alias_name'    => null
                ];
            } else {
                $old = $existingMap[$key];

                // 核心防抖 1: 如果当前已经重新检测到该资产，立即清空历史 missing_count
                if (($old['missing_count'] ?? 0) > 0 || $old['status'] !== 'active') {
                    Database::update('subdomains', [
                        'status'        => 'active',
                        'missing_count' => 0,
                        'last_seen_at'  => date('Y-m-d H:i:s')
                    ], 'id = ?', [$old['id']]);
                }

                if ($old['record_value'] !== $r['value']) {
                    // 核心过滤 2: 判断是否为 Cloudflare / CDN 内部正常 Anycast IP 漂移
                    $isCdnManaged = !empty($cdnManagedSubs[$r['subdomain']]);
                    $isBenign = CdnDriftFilter::isBenignCdnDrift(
                        $old['record_value'],
                        $r['value'],
                        $isCdnManaged,
                        $r['cname_chain'] ?? ($old['cname_chain'] ?? null)
                    );

                    if ($isBenign) {
                        // 属于良性 CDN Anycast 轮换：保持静默，更新数据库最新值，不触发报警！
                        Database::update('subdomains', [
                            'record_value' => $r['value'],
                            'last_seen_at' => date('Y-m-d H:i:s')
                        ], 'id = ?', [$old['id']]);
                    } else {
                        // 属于真实源站变动 (如从 CDN 切回真实独立 IP，或 CNAME 指向被修改)
                        $nameInfo = $this->nameResolver->resolve(
                            $r['subdomain'],
                            $domain['domain'],
                            $r['record_type'],
                            $r['value'],
                            $old['alias_name'] ?? null,
                            $proxy
                        );

                        $type = ($r['record_type'] === 'TXT') ? 'txt_update' : 'changed';
                        $changes[] = [
                            'domain_id'         => $domain['id'],
                            'subdomain'         => $r['subdomain'],
                            'asset_name'        => $nameInfo['asset_name'],
                            'asset_name_source' => $nameInfo['asset_name_source'],
                            'provenance_source' => $primarySource,
                            'priority_level'    => $priority,
                            'record_type'       => $r['record_type'],
                            'change_type'       => $type,
                            'old_value'         => $old['record_value'],
                            'new_value'         => $r['value']
                        ];

                        Database::update('subdomains', [
                            'asset_name'            => $nameInfo['asset_name'],
                            'asset_name_source'     => $nameInfo['asset_name_source'],
                            'asset_name_updated_at' => $nameInfo['asset_name_updated_at'],
                            'record_value'          => $r['value'],
                            'takeover_risk'         => $r['takeover_risk'] ?? 0,
                            'takeover_reason'       => $r['takeover_reason'] ?? null,
                            'cname_chain'           => $r['cname_chain'] ?? null,
                            'status'                => 'active',
                            'missing_count'         => 0,
                            'last_seen_at'          => date('Y-m-d H:i:s')
                        ], 'id = ?', [$old['id']]);
                    }
                } else {
                    Database::update('subdomains', [
                        'last_seen_at'    => date('Y-m-d H:i:s'),
                        'takeover_risk'   => $r['takeover_risk'] ?? 0,
                        'takeover_reason' => $r['takeover_reason'] ?? null
                    ], 'id = ?', [$old['id']]);
                }
            }
        }

        // 4. 核心防抖 3: 针对历史存活资产未在本次批次出现的处理 (NXDOMAIN 3轮确认防误报)
        foreach ($existingMap as $k => $old) {
            if (!isset($currentMap[$k]) && $old['status'] === 'active') {
                // 第一步：使用备用 DoH 端点做一次快速即时复核，避免网络丢包
                $retryRes = $this->dohClient->resolve($old['subdomain'], $old['record_type'], $proxy);
                if (!empty($retryRes['records'])) {
                    // 备用端点成功复查到，说明只是刚才并发瞬间超时，更新活跃时间并跳过失效判定
                    Database::update('subdomains', [
                        'last_seen_at'  => date('Y-m-d H:i:s'),
                        'missing_count' => 0
                    ], 'id = ?', [$old['id']]);
                    continue;
                }

                // 第二步：防抖计数累加
                $curMissing = (int)($old['missing_count'] ?? 0) + 1;

                if ($curMissing < 3) {
                    // 未达到 3 次连续确认阈值：保持 active 状态，仅累加计数，绝不触发误报通知！
                    Database::update('subdomains', [
                        'missing_count' => $curMissing
                    ], 'id = ?', [$old['id']]);
                } else {
                    // 达到连续 3 轮均无响应确认：正式判定为解析失效 (NXDOMAIN) 并触发通知
                    $changes[] = [
                        'domain_id'         => $domain['id'],
                        'subdomain'         => $old['subdomain'],
                        'asset_name'        => $old['asset_name'] ?: $old['subdomain'],
                        'asset_name_source' => $old['asset_name_source'] ?: 'hostname',
                        'provenance_source' => 'snapshot_diff',
                        'priority_level'    => 'normal',
                        'record_type'       => $old['record_type'],
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

        // 5. 将真正实质性的变动记录落库
        foreach ($changes as $c) {
            Database::insert('change_logs', array_merge($c, ['created_at' => date('Y-m-d H:i:s')]));
        }

        $snapshotJson = json_encode($records, JSON_UNESCAPED_UNICODE);
        Database::insert('dns_snapshots', [
            'domain_id'     => $domain['id'],
            'task_id'       => $taskId,
            'snapshot_hash' => hash('sha256', $snapshotJson),
            'total_records' => count($records),
            'snapshot_data' => $snapshotJson,
            'created_at'    => date('Y-m-d H:i:s')
        ]);

        Database::update('domains', [
            'subdomain_count' => count($currentMap),
            'last_scanned_at' => date('Y-m-d H:i:s')
        ], 'id = ?', [$domain['id']]);

        return $changes;
    }

    private function calculatePriority(string $source, bool $isTakeover): string
    {
        if ($isTakeover) return 'critical';
        if (in_array($source, ['crt.sh', 'certspotter', 'tls_san'], true)) return 'high';
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
