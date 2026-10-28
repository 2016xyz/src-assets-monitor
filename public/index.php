<?php

// 生产环境安全错误配置 (不裸露敏感堆栈，统一由 Response 格式化输出)
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
ini_set('display_errors', '0');

// 若通过 PHP 内置开发服务器启动 (php -S)，且请求的是非 PHP 静态资源文件，则直接返回 false 让内置服务器原生处理
if (PHP_SAPI === 'cli-server') {
    $filePath = __DIR__ . parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    if (is_file($filePath) && !str_ends_with($filePath, '.php')) {
        return false;
    }
}

require_once dirname(__DIR__) . '/autoload.php';

use App\Core\App;
use App\Core\Request;
use App\Core\Response;
use App\Core\Router;
use App\Middleware\EnsureSystemInstalled;

// 跨域响应头设置
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Install-Token');

if (strtoupper($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

try {
    $request = new Request();
    $router = new Router();

    // 全局中间件：安装态拦截
    $router->use(function ($req) {
        EnsureSystemInstalled::handle($req);
    });

    // 载入路由注册表
    require_once App::basePath('routes/api.php');

    $router->dispatch($request);
} catch (\Throwable $e) {
    Response::error('系统执行异常: ' . $e->getMessage(), 500, 500, [
        'error_type' => basename(str_replace('\\', '/', get_class($e)))
    ]);
}
