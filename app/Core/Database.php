<?php

namespace App\Core;

use PDO;
use Exception;
use PDOException;
use InvalidArgumentException;

class Database
{
    private static ?PDO $pdo = null;

    public static function getPdo(): PDO
    {
        if (self::$pdo === null) {
            self::$pdo = self::createConnection();
        }
        return self::$pdo;
    }

    public static function createConnection(?array $customConfig = null): PDO
    {
        $driver = $customConfig['driver'] ?? App::env('DB_CONNECTION', 'mysql');
        $host = $customConfig['host'] ?? App::env('DB_HOST', '127.0.0.1');
        $port = $customConfig['port'] ?? App::env('DB_PORT', 3306);
        $dbName = $customConfig['database'] ?? App::env('DB_DATABASE', 'src_monitor');
        $user = $customConfig['username'] ?? App::env('DB_USERNAME', 'root');
        $pass = $customConfig['password'] ?? App::env('DB_PASSWORD', '');

        if ($driver === 'sqlite' || (!extension_loaded('pdo_mysql') && extension_loaded('pdo_sqlite'))) {
            $sqlitePath = App::runtimePath('data.sqlite');
            $pdo = new PDO("sqlite:{$sqlitePath}", null, null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
            $pdo->exec("PRAGMA foreign_keys = ON;");
            return $pdo;
        }

        try {
            $dsn = "mysql:host={$host};port={$port};dbname={$dbName};charset=utf8mb4";
            return new PDO($dsn, $user, $pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_TIMEOUT => 5
            ]);
        } catch (PDOException $e) {
            throw new \RuntimeException("无法连接到 MySQL 数据库 [{$host}:{$port}/{$dbName}]，请检查凭据与网络", 500, $e);
        }
    }

    /**
     * 严谨验证表名和字段标识符，阻断列名/表名 SQL 注入
     */
    public static function validateIdentifier(string $identifier): string
    {
        // 仅允许字母、数字和下划线，禁止反引号、空格、分号等任何特殊符号
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $identifier)) {
            throw new InvalidArgumentException("非法数据库标识符检测到潜在注入攻击: [{$identifier}]");
        }
        return $identifier;
    }

    /**
     * 严谨验证表名或 JOIN 表达式，支持单表、带别名及安全 JOIN 语句
     */
    public static function validateTableExpression(string $table): string
    {
        $table = trim($table);
        // 1. 单表名称: 仅允许字母数字下划线
        if (preg_match('/^[a-zA-Z0-9_]+$/', $table)) {
            return "`{$table}`";
        }

        // 2. 表加简单别名: 如 "domains d"
        if (preg_match('/^([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_]+)$/', $table, $m)) {
            return "`{$m[1]}` `{$m[2]}`";
        }

        // 3. 包含 JOIN 的安全表连接表达式
        // 确保不包含高危特殊字符：分号、引号、注释符号、括号等
        if (preg_match('/[;\'"()\\#\/\*\-]/', $table)) {
            throw new InvalidArgumentException("非法数据库表连接表达式检测到潜在注入攻击: [{$table}]");
        }

        // 严禁包含高危 SQL 关键词（如 UNION, SELECT, INSERT, DROP 等）
        if (preg_match('/\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|BENCHMARK|SLEEP)\b/i', $table)) {
            throw new InvalidArgumentException("非法数据库关键字检测到潜在注入攻击: [{$table}]");
        }

        // 仅允许安全的字符集合 (字母、数字、下划线、空格、点、等号、反引号)
        if (!preg_match('/^[a-zA-Z0-9_\s\.\=\`]+$/', $table)) {
            throw new InvalidArgumentException("非法表表达式字符: [{$table}]");
        }

        return $table;
    }

    public static function query(string $sql, array $params = []): \PDOStatement
    {
        $stmt = self::getPdo()->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    public static function fetchOne(string $sql, array $params = []): ?array
    {
        $stmt = self::query($sql, $params);
        $res = $stmt->fetch();
        return $res ?: null;
    }

    public static function fetchAll(string $sql, array $params = []): array
    {
        $stmt = self::query($sql, $params);
        return $stmt->fetchAll();
    }

    public static function insert(string $table, array $data): int
    {
        $safeTable = self::validateIdentifier($table);
        if (empty($data)) {
            throw new InvalidArgumentException("插入操作数据不可为空");
        }

        $safeKeys = [];
        $values = [];
        foreach ($data as $k => $v) {
            $safeKeys[] = self::validateIdentifier($k);
            $values[] = $v;
        }

        $fields = implode('`, `', $safeKeys);
        $placeholders = implode(', ', array_fill(0, count($safeKeys), '?'));
        $sql = "INSERT INTO `{$safeTable}` (`{$fields}`) VALUES ({$placeholders})";
        
        self::query($sql, $values);
        return (int)self::getPdo()->lastInsertId();
    }

    public static function update(string $table, array $data, string $where, array $whereParams = []): int
    {
        $safeTable = self::validateIdentifier($table);
        if (empty($data)) {
            return 0;
        }

        $sets = [];
        $params = [];
        foreach ($data as $col => $val) {
            $safeCol = self::validateIdentifier($col);
            $sets[] = "`{$safeCol}` = ?";
            $params[] = $val;
        }

        $setString = implode(', ', $sets);
        $sql = "UPDATE `{$safeTable}` SET {$setString} WHERE {$where}";
        $stmt = self::query($sql, array_merge($params, $whereParams));
        return $stmt->rowCount();
    }

    public static function delete(string $table, string $where, array $whereParams = []): int
    {
        $safeTable = self::validateIdentifier($table);
        $sql = "DELETE FROM `{$safeTable}` WHERE {$where}";
        $stmt = self::query($sql, $whereParams);
        return $stmt->rowCount();
    }

    public static function count(string $table, string $where = '1=1', array $params = []): int
    {
        $safeFrom = self::validateTableExpression($table);
        $sql = "SELECT COUNT(*) as cnt FROM {$safeFrom} WHERE {$where}";
        $res = self::fetchOne($sql, $params);
        return (int)($res['cnt'] ?? 0);
    }
}
