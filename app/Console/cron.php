<?php

require_once dirname(__DIR__, 2) . '/autoload.php';

use App\Core\Database;
use App\Middleware\EnsureSystemInstalled;
use App\Services\Notifier\NotificationManager;
use App\Services\Proxy\CircuitBreaker;
use App\Services\Proxy\DoHProxyClient;
use App\Services\Proxy\ProxyHealthChecker;
use App\Services\Proxy\ProxyRateLimiter;
use App\Services\Proxy\ProxyScheduler;
use App\Services\Scanner\SubdomainScanner;

// 若系统尚未完成首次安装，静默跳过
if (!EnsureSystemInstalled::check()) {
    echo "[" . date('Y-m-d H:i:s') . "] 系统尚未完成首次安装向导配置，自动跳过本轮巡检。\n";
    exit(0);
}

echo "[" . date('Y-m-d H:i:s') . "] 启动自动化资产检测与代理维护轮询...\n";

$cb = new CircuitBreaker();
$rl = new ProxyRateLimiter();
$scheduler = new ProxyScheduler($cb, $rl);
$doh = new DoHProxyClient($cb);
$scanner = new SubdomainScanner($doh, $scheduler);
$notifier = new NotificationManager($scheduler);
$healthChecker = new ProxyHealthChecker($cb);

// 1. 代理健康周期巡检 (每 5 分钟探测一次)
$proxies = Database::fetchAll("SELECT * FROM proxies WHERE status = 1");
foreach ($proxies as $p) {
    $last = strtotime($p['last_check_at'] ?? '2000-01-01');
    if (time() - $last >= 300) {
        $res = $healthChecker->check($p);
        echo " - 代理 [{$p['name']}]: " . ($res['healthy'] ? "健康 (延迟 {$res['latency_ms']}ms)" : "异常") . "\n";
    }
}

// 2. 主域名周期性巡检与每日主动字典爆破
$domains = Database::fetchAll("SELECT * FROM domains WHERE is_enabled = 1");
foreach ($domains as $domain) {
    $lastScanned = strtotime($domain['last_scanned_at'] ?? '2000-01-01');
    $diffMinutes = (time() - $lastScanned) / 60;

    $interval = match ($domain['check_interval'] ?? '1h') {
        '10m'   => 10,
        '1d'    => 1440,
        default => 60,
    };

    if ($diffMinutes >= $interval) {
        $lastBrute = !empty($domain['last_brute_at']) ? strtotime($domain['last_brute_at']) : 0;
        $needDailyBrute = (time() - $lastBrute >= 86400) || empty($domain['last_brute_at']);
        $modeDesc = $needDailyBrute ? "包含【每日大字典爆破】" : "轻量快速存活监控";

        echo " - 开始巡检域名 [{$domain['domain']}] ({$modeDesc})...\n";

        $taskId = Database::insert('scan_tasks', [
            'domain_id'    => $domain['id'],
            'trigger_type' => 'auto',
            'status'       => 'running',
            'started_at'   => date('Y-m-d H:i:s'),
            'created_at'   => date('Y-m-d H:i:s')
        ]);

        try {
            // 传入每日爆破标志
            $res = $scanner->scan($domain, $taskId, $needDailyBrute);
            Database::update('scan_tasks', [
                'status'           => 'success',
                'discovered_count' => $res['total_active'],
                'changes_count'    => count($res['changes']),
                'finished_at'      => date('Y-m-d H:i:s')
            ], 'id = ?', [$taskId]);

            if (!empty($res['changes'])) {
                echo "   发现 " . count($res['changes']) . " 条解析异动，触发告警分发...\n";
                $notifier->dispatchBatch($domain, $res['changes']);
            }
        } catch (\Throwable $e) {
            Database::update('scan_tasks', [
                'status'        => 'failed',
                'error_message' => $e->getMessage(),
                'finished_at'   => date('Y-m-d H:i:s')
            ], 'id = ?', [$taskId]);
            echo "   巡检异常: " . $e->getMessage() . "\n";
        }
    }
}

echo "[" . date('Y-m-d H:i:s') . "] 任务批次结束。\n";
