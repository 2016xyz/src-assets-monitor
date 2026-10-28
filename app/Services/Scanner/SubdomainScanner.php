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
            usleep(mt_rand(150000, 300000)); // 随机物理微抖动
        }

        // 7. 阶段六：CNAME 链追踪与云存储桶接管检测
        $this->logTask($taskId, 'cname_takeover', 'info', "正在分析 CNAME 链与云存储/SaaS 悬挂接管风险");
        $analyzedRecords = $this->enrichCnameAndTakeover($activeRecords, $proxy);

        // 8. 阶段七：对存活 Web 资产挖掘 JavaScript 与 Source Map
        $this->logTask($taskId, 'js_crawl', 'info', "对存活 Web 资产提取 JavaScript 与 Source Map 深度挖掘");
        $jsDiscovered = $this->extractFromWebAssets($analyzedRecords, $domain['domain'], $proxy);
        if (!empty($jsDiscovered)) {
            $this->logTask($taskId, 'js_crawl', 'info', "JS 深度挖掘出额外 " . count($jsDiscovered) . " 个潜在内部端点");
            // 对新挖掘出的资产补探一次 A 记录
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

        // 9. 阶段八：快照比对、资产名称自动识别与持久化
        $this->logTask($taskId, 'snapshot_diff', 'info', "执行多维快照比对与资产名称优先级链识别");
        $changes = $this->diffAndPersistExtended($domain, $taskId, $analyzedRecords, $proxy);

        return [
            'total_active' => count($analyzedRecords),
            'changes'      => $changes
        ];
    }

    /**
     * 字典生成与置换拓展 ({env}.{word}, {word}-{env}, {word}{数字})
     */
    private function generatePermutationDictionary(string $mainDomain): array
    {
        $baseDict = ['www', 'mail', 'api', 'admin', 'test', 'dev', 'vpn', 'oa', 'git', 'jenkins', 'auth', 'portal'];
        $row = Database::fetchOne("SELECT value FROM settings WHERE key = 'dictionary_subdomains'");
        if ($row && !empty($row['value'])) {
            $parsed = json_decode($row['value'], true);
            if (is_array($parsed)) $baseDict = $parsed;
        }

        $environments = ['dev', 'test', 'uat', 'stg', 'prod', 'inner', 'corp'];
        $generated = $baseDict;

        // 置换生成
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

    /**
     * CNAME 链与云存储桶接管检测
     */
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
                    // 只读检测云存储桶是否存在
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

    /**
     * 从 Web 资产提取 JavaScript 与 Source Map
     */
    private function extractFromWebAssets(array $records, string $mainDomain, ?array $proxy): array
    {
        $discovered = [];
        $tested = 0;

        foreach ($records as $r) {
            if ($tested >= 3) break; // 控制成本，只探前 3 个存活 Web
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
     * 扩展快照比对与名称识别 (记录来源 provenance、优先级与接管标志)
     */
    private function diffAndPersistExtended(array $domain, int $taskId, array $records, ?array $proxy): array
    {
        $existing = Database::fetchAll("SELECT * FROM subdomains WHERE domain_id = ?", [$domain['id']]);
        $existingMap = [];
        foreach ($existing as $ex) {
            $existingMap["{$ex['subdomain']}:{$ex['record_type']}"] = $ex;
        }

        $currentMap = [];
        $changes = [];

        foreach ($records as $r) {
            $key = "{$r['subdomain']}:{$r['record_type']}";
            $currentMap[$key] = $r;
            $sourcesJson = json_encode($r['sources'] ?? ['unknown'], JSON_UNESCAPED_UNICODE);
            $primarySource = ($r['sources'][0] ?? 'unknown');

            // 计算通知优先级
            $priority = $this->calculatePriority($primarySource, !empty($r['takeover_risk']));

            if (!isset($existingMap[$key])) {
                // 🆕 全新子域名资产
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

                Database::insert('subdomains', [
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
                    'takeover_risk'         => $r['takeover_risk'] ?? 0,
                    'takeover_reason'       => $r['takeover_reason'] ?? null,
                    'cname_chain'           => $r['cname_chain'] ?? null,
                    'provenance_sources'    => $sourcesJson,
                    'first_seen_at'         => date('Y-m-d H:i:s'),
                    'last_seen_at'          => date('Y-m-d H:i:s'),
                    'created_at'            => date('Y-m-d H:i:s')
                ]);
            } else {
                $old = $existingMap[$key];
                if ($old['record_value'] !== $r['value']) {
                    // 🔄 解析记录变更
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
                        'last_seen_at'          => date('Y-m-d H:i:s')
                    ], 'id = ?', [$old['id']]);
                } else {
                    Database::update('subdomains', [
                        'last_seen_at'       => date('Y-m-d H:i:s'),
                        'takeover_risk'      => $r['takeover_risk'] ?? 0,
                        'takeover_reason'    => $r['takeover_reason'] ?? null
                    ], 'id = ?', [$old['id']]);
                }
            }
        }

        // ❌ 失效判定
        foreach ($existingMap as $k => $old) {
            if (!isset($currentMap[$k]) && $old['status'] === 'active') {
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
                Database::update('subdomains', ['status' => 'nxdomain'], 'id = ?', [$old['id']]);
            }
        }

        foreach ($changes as $c) {
            Database::insert('change_logs', array_merge($c, ['created_at' => date('Y-m-d H:i:s')]));
        }

        // 全量快照归档
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

    /**
     * 计算来源与风险优先级
     * CT 日志新出现 > 主动爆破 > 第三方 API > 搜索/泄露
     */
    private function calculatePriority(string $source, bool $isTakeover): string
    {
        if ($isTakeover) {
            return 'critical'; // 接管风险最高级
        }
        if (in_array($source, ['crt.sh', 'certspotter', 'tls_san'], true)) {
            return 'high';     // 证书日志即时级别
        }
        if (in_array($source, ['brute_enum', 'axfr'], true)) {
            return 'high';
        }
        if (in_array($source, ['github_dork', 'js_sourcemap'], true)) {
            return 'normal';
        }
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
