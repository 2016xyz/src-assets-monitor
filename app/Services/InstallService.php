<?php

namespace App\Services;

use App\Core\App;
use App\Core\Cache;
use App\Core\Database;
use PDO;

class InstallService
{
    private const TOKEN_PREFIX = 'src_install_token:';

    public function generateInstallToken(string $clientIp): string
    {
        $token = hash('sha256', bin2hex(random_bytes(20)) . microtime(true) . $clientIp);
        Cache::set(self::TOKEN_PREFIX . $token, $clientIp, 300);
        return $token;
    }

    public function verifyInstallToken(?string $token, string $clientIp): bool
    {
        if (empty($token)) {
            return false;
        }
        $cachedIp = Cache::get(self::TOKEN_PREFIX . $token);
        return !empty($cachedIp) && $cachedIp === $clientIp;
    }

    public function checkEnvironment(): array
    {
        $phpVersion = PHP_VERSION;
        $phpPassed = version_compare($phpVersion, '8.0.0', '>=');

        $requiredExtensions = [
            'mbstring'  => '多字节字符串处理',
            'openssl'   => '凭据与通信高强度加密',
            'curl'      => '网络出站与代理请求驱动',
            'fileinfo'  => '字典与文件类型安全检测',
            'sockets'   => '底层网络连接与套接字支持'
        ];

        $extChecks = [];
        $allPassed = $phpPassed;

        foreach ($requiredExtensions as $ext => $desc) {
            $loaded = extension_loaded($ext);
            if (!$loaded) {
                $allPassed = false;
            }
            $extChecks[] = [
                'name'        => $ext,
                'description' => $desc,
                'status'      => $loaded ? 'pass' : 'fail',
                'suggestion'  => $loaded ? '正常' : "请执行 apt/yum install php-{$ext}"
            ];
        }

        // 数据库驱动支持 (优先 pdo_mysql，兼容 pdo_sqlite)
        $hasMysql = extension_loaded('pdo_mysql');
        $hasSqlite = extension_loaded('pdo_sqlite');
        $extChecks[] = [
            'name'        => 'pdo_mysql',
            'description' => 'MySQL 生产级数据库连接驱动',
            'status'      => $hasMysql ? 'pass' : ($hasSqlite ? 'warn' : 'fail'),
            'suggestion'  => $hasMysql ? '就绪' : ($hasSqlite ? '未安装 pdo_mysql，将兼容启用 SQLite 模式' : '必须安装 pdo_mysql 或 pdo_sqlite')
        ];

        // 核心目录可写检测
        $writableDirs = [
            App::runtimePath() => '运行时缓存与日志目录 (runtime/)',
            App::basePath()    => '根目录环境变量写权限 (.env)'
        ];

        $dirChecks = [];
        foreach ($writableDirs as $path => $desc) {
            $writable = is_writable($path) || (!file_exists($path) && is_writable(dirname($path)));
            if (!$writable) {
                $allPassed = false;
            }
            $dirChecks[] = [
                'path'        => $desc,
                'status'      => $writable ? 'pass' : 'fail',
                'suggestion'  => $writable ? '具备写入权限' : "请执行: chmod -R 777 {$path}"
            ];
        }

        $curlVersion = curl_version();
        $proxyCapable = in_array('socks5', $curlVersion['protocols'] ?? [], true);

        return [
            'can_proceed' => $allPassed,
            'php_version' => [
                'current'    => $phpVersion,
                'required'   => '>= 8.0.0 (生产建议 8.1+)',
                'status'     => $phpPassed ? 'pass' : 'fail',
                'suggestion' => $phpPassed ? '版本符合' : '请升级 PHP 运行时'
            ],
            'extensions'  => $extChecks,
            'permissions' => $dirChecks,
            'curl_proxy'  => [
                'status'     => $proxyCapable ? 'pass' : 'warn',
                'protocols'  => implode(', ', $curlVersion['protocols'] ?? []),
                'suggestion' => $proxyCapable ? '支持 HTTP/SOCKS5' : 'curl 建议安装完整协议包'
            ]
        ];
    }

    public function setupDatabase(array $config): array
    {
        $driver = $config['driver'] ?? (extension_loaded('pdo_mysql') ? 'mysql' : 'sqlite');
        $host = $config['host'] ?? '127.0.0.1';
        $port = (int)($config['port'] ?? 3306);
        $dbName = $config['database'] ?? 'src_monitor';
        $user = $config['username'] ?? 'root';
        $pass = $config['password'] ?? '';
        $autoCreate = (bool)($config['auto_create'] ?? false);

        if ($driver === 'mysql' && extension_loaded('pdo_mysql')) {
            // 测试连接根服务器并尝试自动建库
            if ($autoCreate) {
                $rootPdo = new PDO("mysql:host={$host};port={$port};charset=utf8mb4", $user, $pass, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_TIMEOUT => 3
                ]);
                $rootPdo->exec("CREATE DATABASE IF NOT EXISTS `{$dbName}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;");
            }

            $targetPdo = new PDO("mysql:host={$host};port={$port};dbname={$dbName};charset=utf8mb4", $user, $pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
            ]);

            $sqlFile = App::basePath('database/install.sql');
            $sqlContent = file_get_contents($sqlFile);
            $targetPdo->exec($sqlContent);
        } else {
            // SQLite 兼容测试
            $sqlitePath = App::runtimePath('data.sqlite');
            $targetPdo = new PDO("sqlite:{$sqlitePath}", null, null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
            ]);
            $sqlFile = App::basePath('database/sqlite_schema.sql');
            $sqlContent = file_get_contents($sqlFile);
            $targetPdo->exec($sqlContent);
            $driver = 'sqlite';
        }

        // 回写 .env
        $this->updateEnvFile([
            'DB_CONNECTION' => $driver,
            'DB_HOST'       => $host,
            'DB_PORT'       => (string)$port,
            'DB_DATABASE'   => $dbName,
            'DB_USERNAME'   => $user,
            'DB_PASSWORD'   => $pass,
        ]);

        return [
            'tables_created' => 19,
            'driver'         => $driver,
            'database'       => $dbName
        ];
    }

    public function createAdminAccount(array $adminData): void
    {
        $password = $adminData['password'];
        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,64}$/', $password)) {
            throw new \InvalidArgumentException('管理员密码必须不少于8位，且同时包含大写英文字母、小写英文字母和数字。');
        }

        $existing = Database::fetchOne("SELECT id FROM users WHERE username = ?", [$adminData['username']]);
        if ($existing) {
            Database::update('users', [
                'email'    => $adminData['email'],
                'password' => password_hash($password, PASSWORD_BCRYPT),
                'role'     => 'admin',
                'status'   => 1
            ], 'id = ?', [$existing['id']]);
        } else {
            Database::insert('users', [
                'username'   => $adminData['username'],
                'email'      => $adminData['email'],
                'password'   => password_hash($password, PASSWORD_BCRYPT),
                'role'       => 'admin',
                'status'     => 1,
                'created_at' => date('Y-m-d H:i:s')
            ]);
        }
    }

    public function configureNotifications(array $channels): void
    {
        foreach ($channels as $chan) {
            if (empty($chan['type']) || empty($chan['name'])) continue;
            Database::insert('notify_channels', [
                'name'       => $chan['name'],
                'type'       => $chan['type'],
                'config'     => json_encode($chan['config'] ?? [], JSON_UNESCAPED_UNICODE),
                'status'     => 1,
                'created_at' => date('Y-m-d H:i:s')
            ]);
        }
    }

    public function finalizeInstallation(string $token, string $clientIp): void
    {
        Database::query("UPDATE `settings` SET `value` = '1' WHERE `key` = 'installed'");
        Database::query("UPDATE `settings` SET `value` = ? WHERE `key` = 'install_time'", [date('Y-m-d H:i:s')]);

        $lockContent = json_encode([
            'installed_at' => date('c'),
            'version_hash' => hash('sha256', microtime(true) . bin2hex(random_bytes(16))),
            'installer_ip' => $clientIp
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        file_put_contents(App::runtimePath('install.lock'), $lockContent);
        Cache::delete(self::TOKEN_PREFIX . $token);
    }

    private function updateEnvFile(array $values): void
    {
        $envPath = App::basePath('.env');
        if (!file_exists($envPath)) {
            $example = App::basePath('.env.example');
            if (file_exists($example)) {
                copy($example, $envPath);
            } else {
                touch($envPath);
            }
        }

        $content = file_get_contents($envPath);
        foreach ($values as $key => $val) {
            $escaped = preg_match('/\s/', $val) ? '"' . addcslashes($val, '"') . '"' : $val;
            if (preg_match("/^{$key}=/m", $content)) {
                $content = preg_replace("/^{$key}=.*/m", "{$key}={$escaped}", $content);
            } else {
                $content .= PHP_EOL . "{$key}={$escaped}";
            }
        }
        file_put_contents($envPath, $content);
    }
}
