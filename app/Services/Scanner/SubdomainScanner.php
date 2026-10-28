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
        $this->logTask($taskId, 'passive_multi', 'info', "开始对 [{$domain['domain']}] 执行全景资产多轨深度探测");

        // 1. 确定出口代理
        $proxy = null;
        if ($domain['proxy_mode'] === 'proxy_group' && !empty($domain['proxy_group_id'])) {
            $proxy = $this->scheduler->selectProxy((int)$domain['proxy_group_id'], $domain['domain']);
        }

        $candidatesPool = []; // [subdomain => ['sources' => [...]]]

        // 2. 阶段一：多源被动并发采集 (crt.sh/CertSpotter/RapidDNS/ThreatMiner/Wayback/OTX/Bing...)
        $this->logTask($taskId, 'passive_multi', 'info', "正在并发采集 CT 证书日志、历史快照、搜索引擎与 DNS 关联源");
        $passiveResults = $this->passivePool->collectAll($domain['domain'], $proxy);
        foreach ($passiveResults as $sub => $meta) {
            $candidatesPool[$sub] = $meta;
        }
        $this->logTask($taskId, 'passive_multi', 'info', "被动多源聚合提取到 " . count($passiveResults) . " 个候选子域名");

        // 3. 阶段二：AXFR 区域传送 (显式开启时探测)
        if (!empty($domain['enable_axfr'])) {
            $this->logTask($taskId, 'axfr_probe', 'info', "执行 DNS 区域传送 (AXFR) 弱点探测");
            $axfrRes = $this->axfrScanner->probeAxfr($domain['domain'], $proxy);
            if ($axfrRes['vulnerable']) {
                $this->logTask($taskId, 'axfr_probe', 'warn', "权威 DNS 存在区域传送漏洞！提取 " . count($axfrRes['records']) . " 条记录");
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
                $this->logTask($taskId, 'wildcard_check', 'warn', "检测到目标主域存在泛解析！捕获特征: " . implode(', ', array_merge($wildcardInfo['wildcard_ips'], $wildcardInfo['wildcard_cnames'])));
            }
        }

        // 6. 阶段五：企业级超大字典置换生成 (单字母/双字母/高频词/多级衍生)
        $dict = $this->generatePermutationDictionary($domain['domain'], array_keys($candidatesPool));
        foreach ($dict as $w) {
            $sub = "{$w}.{$domain['domain']}";
            $this->appendCandidate($candidatesPool, $sub, 'brute_enum');
        }

        $totalCandidates = count($candidatesPool);
        $this->logTask($taskId, 'brute_dns', 'info', "全源候选池汇总就绪，共计 {$totalCandidates} 个，启动高性能并发 DoH 批量解析");

        // 7. 高性能并发批量 DoH 解析 (使用 curl_multi 40并发并行查询)
        $activeRecords = [];
        $resolvedSubs = [];
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
                    [$sub, $type] = explode(':', $queryKey);
                    foreach ($answers as $r) {
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
                        $resolvedSubs[$sub] = true;
                    }
                }
            }
            usleep(50000); // 50ms 微间隔
        }

        // 8. 阶段六：CNAME 链追踪与云存储桶接管检测
        $this->logTask($taskId, 'cname_takeover', 'info', "分析 CNAME 链与云存储/SaaS 悬挂接管风险");
        $analyzedRecords = $this->enrichCnameAndTakeover($activeRecords, $proxy);

        // 9. 阶段七：存活 Web 资产深入提取 JS 与 Source Map
        $this->logTask($taskId, 'js_crawl', 'info', "存活 Web 资产提取 JavaScript 与 Source Map 深度挖掘");
        $jsDiscovered = $this->extractFromWebAssets($analyzedRecords, $domain['domain'], $proxy);
        if (!empty($jsDiscovered)) {
            $this->logTask($taskId, 'js_crawl', 'info', "JS 深度挖掘出额外 " . count($jsDiscovered) . " 个端点");
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
                    $resolvedSubs[$jsSub] = true;
                }
            }
        }

        // 10. 阶段八：识别被动证书源中存在、但当前 DNS 未解析的历史资产 (保证全景资产 100% 入库)
        $historicalInactive = [];
        foreach ($candidatesPool as $candSub => $candMeta) {
            if (!isset($resolvedSubs[$candSub])) {
                // 来自被动源 (如 crt.sh/certspotter)，但在当前 DNS 中未解析出 A/CNAME 的历史资产
                $isPassive = false;
                foreach ($candMeta['sources'] as $src) {
                    if (in_array($src, ['crt.sh', 'certspotter', 'hackertarget', 'rapiddns', 'wayback_archive', 'threatminer', 'search_engine'], true)) {
                        $isPassive = true;
                        break;
                    }
                }
                if ($isPassive) {
                    $historicalInactive[] = [
                        'subdomain'   => $candSub,
                        'record_type' => 'A',
                        'value'       => '未配置公网解析 (历史证书源)',
                        'ttl'         => 0,
                        'sources'     => $candMeta['sources'],
                        'is_inactive' => true
                    ];
                }
            }
        }

        $this->logTask($taskId, 'snapshot_diff', 'info', "比对快照 (存活记录 " . count($analyzedRecords) . " 条，历史证书资产 " . count($historicalInactive) . " 条)");
        $changes = $this->diffAndPersistExtended($domain, $taskId, $analyzedRecords, $historicalInactive, $proxy);

        return [
            'total_active'     => count($analyzedRecords),
            'total_historical' => count($historicalInactive),
            'changes'          => $changes
        ];
    }

    /**
     * 生成超大复合字典 (单字母/双字母/高频服务/多级子域变异)
     */
    private function generatePermutationDictionary(string $mainDomain, array $existingCandidates = []): array
    {
        // 1. 单字母 (a-z, 0-9)
        $singleLetters = array_merge(range('a', 'z'), range('0', '9'));

        // 2. 双字母高频 (涵盖各类拼音与缩写: sh, wx, bx, st, cp, sp, qc, wa, wd, wy, yl, gc, d5, sr, oa, ai...)
        $twoLetters = [
            'sh', 'wx', 'bx', 'st', 'cp', 'sp', 'qc', 'wa', 'wd', 'wy', 'yl', 'gc', 'd5', 'sr',
            'oa', 'ai', 'it', 'hr', 'bi', 'cs', 'db', 'pr', 'ad', 'gw', 'm1', 'm2', 's1', 's2',
            'v1', 'v2', 'v3', 'ip', 'tc', 'ws', 'im', 'id', 'my', 'up', 'dl', 'go', 'to', 'in',
            'sd', 'bj', 'gz', 'sz', 'hz', 'cd', 'wh', 'nj', 'cq', 'xa', 'fs', 'dg', 'hk', 'tw'
        ];

        // 3. 300+ 核心企业服务与 SRC 高频顶级词汇
        $enterpriseDict = [
            'www', 'api', 'mail', 'admin', 'app', 'm', 'h5', 'wap', 'test', 'dev', 'uat', 'stg', 'prod',
            'pre', 'beta', 'demo', 'stage', 'vpn', 'oa', 'git', 'gitlab', 'svn', 'wiki', 'jira', 'jenkins',
            'auth', 'portal', 'login', 'sso', 'cas', 'pass', 'passport', 'account', 'user', 'member', 'vip',
            'pay', 'payment', 'trade', 'order', 'shop', 'mall', 'client', 'pc', 'web', 'site', 'bbs', 'forum',
            'gateway', 'router', 'proxy', 'ngrok', 'frp', 'rustdesk', 'vnc', 'rdp', 'ssh', 'bastion',
            'harbor', 'k8s', 'nacos', 'apollo', 'eureka', 'consul', 'minio', 'oss', 'cos', 'obs',
            'cdn', 'static', 'res', 'img', 'image', 'file', 'upload', 'download', 'backup', 'bak', 'old',
            'temp', 'tmp', 'new', 'release', 'deploy', 'dispatch', 'job', 'task', 'cron', 'schedule',
            'rabbitmq', 'rocketmq', 'kafka', 'redis', 'mysql', 'sql', 'db', 'database', 'oracle', 'pg',
            'monitor', 'alert', 'notice', 'message', 'sms', 'push', 'zabbix', 'grafana', 'prometheus', 'jaeger',
            'elk', 'kibana', 'trace', 'dubbo', 'emqx', 'mqtt', 'ntp', 'time', 'cert', 'ssl', 'ca', 'acme',
            'cloud', 'yun', 'yun1', 'pan', 'drive', 'share', 'live', 'video', 'stream', 'rtmp', 'meeting',
            'zoom', 'conference', 'voip', 'sip', 'iot', 'edge', 'node', 'server', 'host', 'vps', 'vm',
            'pve', 'pvewin', 'esxi', 'docker', 'portainer', 'kubernetes', 'sonarqube', 'nexus', 'mirrors',
            'repo', 'build', 'graylog', 'sentry', 'flink', 'spark', 'hadoop', 'hive', 'doris', 'clickhouse',
            'tidb', 'elastic', 'opensearch', 'kdyun', 'mali', 'mbti', 'nmap', 'testxss', 'v', 'wji', 'wno',
            'xss', 'zmcp', 'fern', 'pop', 'smtp', 'q', 't', 'open', 'openapi', 'sdk', 'help', 'docs', 'doc',
            'status', 'health', 'report', 'log', 'corp', 'internal', 'inner', 'lan', 'local', 'office',
            'bastion-host', 'sec', 'security', 'soc', 'siem', 'waf', 'ids', 'ips', 'audit', 'vuln'
        ];

        // 4. 用户自定义系统字典
        $customDict = [];
        $row = Database::fetchOne("SELECT `value` FROM `settings` WHERE `key` = 'dictionary_subdomains'");
        if ($row && !empty($row['value'])) {
            $parsed = json_decode($row['value'], true);
            if (is_array($parsed)) $customDict = $parsed;
        }

        $allWords = array_values(array_unique(array_merge($singleLetters, $twoLetters, $enterpriseDict, $customDict)));

        // 5. 常见环境后缀衍生 (如 api-dev, api-test, test1, test2)
        $environments = ['dev', 'test', 'uat', 'stg', 'prod', 'inner', 'internal'];
        $generated = $allWords;

        foreach (array_slice($allWords, 0, 30) as $word) {
            foreach ($environments as $env) {
                $generated[] = "{$word}-{$env}";
                $generated[] = "{$env}-{$word}";
            }
            $generated[] = "{$word}1";
            $generated[] = "{$word}2";
        }

        // 6. 多级子域名衍生 (针对如 cp.domain 生成 api.cp, ap.cp, admin.cp)
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
            if ($tested >= 4) break;
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
     * 快照比对、CDN 漂移平滑过滤、历史未解析资产入库与报警分发
     */
    private function diffAndPersistExtended(array $domain, int $taskId, array $activeRecords, array $inactiveCandidates, ?array $proxy): array
    {
        // 1. 去重合并活跃记录
        $dedupRecords = [];
        foreach ($activeRecords as $r) {
            $dedupKey = "{$r['subdomain']}:{$r['record_type']}";
            $dedupRecords[$dedupKey] = $r;
        }
        $records = array_values($dedupRecords);

        // 2. 载入已有库内记录
        $existing = Database::fetchAll("SELECT * FROM subdomains WHERE domain_id = ?", [$domain['id']]);
        $existingMap = [];
        foreach ($existing as $ex) {
            $existingMap["{$ex['subdomain']}:{$ex['record_type']}"] = $ex;
        }

        // 3. 构建 CDN 托管白名单
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

        // 4. 处理存活解析记录的变更与新增
        foreach ($records as $r) {
            $key = "{$r['subdomain']}:{$r['record_type']}";
            $currentMap[$key] = $r;
            $sourcesJson = json_encode($r['sources'] ?? ['unknown'], JSON_UNESCAPED_UNICODE);
            $primarySource = ($r['sources'][0] ?? 'unknown');
            $priority = $this->calculatePriority($primarySource, !empty($r['takeover_risk']));

            if (!isset($existingMap[$key])) {
                // 全新存活资产发现 ➔ 触发 added 报警
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

                // 如果之前是 nxdomain / 历史未解析，现在恢复活跃 ➔ 激活并重置
                if ($old['status'] !== 'active' || ($old['missing_count'] ?? 0) > 0) {
                    Database::update('subdomains', [
                        'status'        => 'active',
                        'missing_count' => 0,
                        'last_seen_at'  => date('Y-m-d H:i:s')
                    ], 'id = ?', [$old['id']]);
                }

                if ($old['record_value'] !== $r['value']) {
                    // 判断是否属于 CDN 内部良性 Anycast 漂移
                    $isCdnManaged = !empty($cdnManagedSubs[$r['subdomain']]);
                    $isBenign = CdnDriftFilter::isBenignCdnDrift(
                        $old['record_value'],
                        $r['value'],
                        $isCdnManaged,
                        $r['cname_chain'] ?? ($old['cname_chain'] ?? null)
                    );

                    if ($isBenign) {
                        // 良性漂移：静默更新数据库，不发报警骚扰
                        Database::update('subdomains', [
                            'record_value' => $r['value'],
                            'last_seen_at' => date('Y-m-d H:i:s')
                        ], 'id = ?', [$old['id']]);
                    } else {
                        // 真实解析指向变更 (如从 CDN 切出或源站迁移)
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

        // 5. 核心增强：将被动源发现的全部历史未解析资产入库 (无解析但存在历史证书)
        foreach ($inactiveCandidates as $inact) {
            $key = "{$inact['subdomain']}:A";
            $keyCname = "{$inact['subdomain']}:CNAME";

            // 如果该子域名已有活跃 A 或 CNAME 记录，跳过
            if (isset($existingMap[$key]) || isset($existingMap[$keyCname]) || isset($currentMap[$key]) || isset($currentMap[$keyCname])) {
                continue;
            }

            $primarySource = ($inact['sources'][0] ?? 'crt.sh') . ' (历史证书)';
            Database::insert('subdomains', [
                'domain_id'             => $domain['id'],
                'subdomain'             => $inact['subdomain'],
                'asset_name'            => $inact['subdomain'],
                'alias_name'            => null,
                'asset_name_source'     => 'hostname',
                'asset_name_updated_at' => null,
                'record_type'           => 'A',
                'record_value'          => '未配置公网解析 (历史证书源)',
                'source'                => $primarySource,
                'status'                => 'nxdomain',
                'missing_count'         => 0,
                'takeover_risk'         => 0,
                'takeover_reason'       => null,
                'cname_chain'           => null,
                'provenance_sources'    => json_encode($inact['sources'], JSON_UNESCAPED_UNICODE),
                'first_seen_at'         => date('Y-m-d H:i:s'),
                'last_seen_at'          => date('Y-m-d H:i:s'),
                'created_at'            => date('Y-m-d H:i:s')
            ]);
            $existingMap[$key] = true;
        }

        // 6. 3 轮 NXDOMAIN 防抖：针对库内原本活跃但本次未解析的记录
        foreach ($existingMap as $k => $old) {
            if (is_array($old) && !isset($currentMap[$k]) && $old['status'] === 'active') {
                $retryRes = $this->dohClient->resolve($old['subdomain'], $old['record_type'], $proxy);
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

        // 7. 实质性变动落库
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

        // 更新主域名已知子域名总量 (含存活与历史)
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
