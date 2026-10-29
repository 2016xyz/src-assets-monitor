<?php

require_once dirname(__DIR__) . '/autoload.php';

use App\Core\Database;

echo "=== 执行 subdomains 数据去重与 CNAME 字段自动整合 ===\n";

$subs = Database::fetchAll("SELECT * FROM subdomains ORDER BY domain_id ASC, subdomain ASC, id ASC");
$grouped = [];
foreach ($subs as $s) {
    $key = $s['domain_id'] . '_' . $s['subdomain'];
    $grouped[$key][] = $s;
}

echo "唯一子域名基数: " . count($grouped) . "\n";

foreach ($grouped as $k => $items) {
    if (count($items) <= 1) continue;

    $primary = null;
    $cnameVal = null;

    foreach ($items as $it) {
        if ($it['record_type'] === 'CNAME') {
            $cnameVal = $it['record_value'];
        }
        if ($it['record_type'] === 'A' && $it['status'] === 'active') {
            $primary = $it;
        }
    }
    if (!$primary) {
        $primary = $items[0];
    }

    if ($cnameVal && $cnameVal !== $primary['record_value']) {
        Database::update('subdomains', ['cname_record' => $cnameVal], 'id = ?', [$primary['id']]);
    }

    foreach ($items as $it) {
        if ($it['id'] !== $primary['id']) {
            Database::delete('subdomains', 'id = ?', [$it['id']]);
        }
    }
}

$remaining = Database::count('subdomains');
echo "去重整合后唯一子域名记录数: {$remaining}\n";
