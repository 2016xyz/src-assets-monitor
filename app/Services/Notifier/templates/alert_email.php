<?php

/**
 * 资产监控告警邮件纯文本与 HTML 模板渲染器
 */
return function(array $params): string {
    $assetName = $params['asset_name'] ?? '';
    $subdomain = $params['subdomain'] ?? '';
    $domain = $params['domain'] ?? '';
    $changeType = $params['change_type'] ?? '';
    $newValue = $params['new_value'] ?? '无 (NXDOMAIN)';
    $source = $params['asset_name_source'] ?? 'hostname';
    $time = $params['time'] ?? date('Y-m-d H:i:s');

    // 回退规则：为空或等于子域名时，追加 (名称未识别)
    $displayName = $assetName;
    if (empty($displayName) || $displayName === $subdomain) {
        $displayName = "{$subdomain} (名称未识别)";
    }

    // 中文化映射
    $sourceLabels = [
        'alias'       => '自定义',
        'http_title'  => '网页标题',
        'http_server' => '服务器标识',
        'cname'       => 'CNAME 目标',
        'ptr'         => '反查名称',
        'hostname'    => '未识别'
    ];
    $displaySource = $sourceLabels[$source] ?? '未识别';

    return "资产监控告警\n" .
           "────────────────\n" .
           "资产名称：{$displayName}\n" .
           "子域名：  {$subdomain}\n" .
           "主域名：  {$domain}\n" .
           "变更类型：{$changeType}\n" .
           "解析记录：{$newValue}\n" .
           "名称来源：{$displaySource}\n" .
           "发现时间：{$time}\n" .
           "────────────────\n" .
           "来源：SRC 资产检测站";
};
