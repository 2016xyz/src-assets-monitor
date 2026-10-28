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
        // 允许类似于 "domains d" 的简单别名，但禁止复杂注入
        $parts = explode(' ', trim($table));
        $safeTable = self::validateIdentifier($parts[0]);
        $alias = isset($parts[1]) ? ' ' . self::validateIdentifier($parts[1]) : '';

        $sql = "SELECT COUNT(*) as cnt FROM `{$safeTable}`{$alias} WHERE {$where}";
        $res = self::fetchOne($sql, $params);
        return (int)($res['cnt'] ?? 0);
    }
}
