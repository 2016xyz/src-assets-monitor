<?php

namespace App\Core;

use PDO;
use Exception;
use PDOException;

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
        $keys = array_keys($data);
        $fields = implode('`, `', $keys);
        $placeholders = implode(', ', array_fill(0, count($keys), '?'));
        $sql = "INSERT INTO `{$table}` (`{$fields}`) VALUES ({$placeholders})";
        self::query($sql, array_values($data));
        return (int)self::getPdo()->lastInsertId();
    }

    public static function update(string $table, array $data, string $where, array $whereParams = []): int
    {
        $sets = [];
        $params = [];
        foreach ($data as $col => $val) {
            $sets[] = "`{$col}` = ?";
            $params[] = $val;
        }
        $setString = implode(', ', $sets);
        $sql = "UPDATE `{$table}` SET {$setString} WHERE {$where}";
        $stmt = self::query($sql, array_merge($params, $whereParams));
        return $stmt->rowCount();
    }

    public static function delete(string $table, string $where, array $whereParams = []): int
    {
        $sql = "DELETE FROM `{$table}` WHERE {$where}";
        $stmt = self::query($sql, $whereParams);
        return $stmt->rowCount();
    }

    public static function count(string $table, string $where = '1=1', array $params = []): int
    {
        $sql = "SELECT COUNT(*) as cnt FROM `{$table}` WHERE {$where}";
        $res = self::fetchOne($sql, $params);
        return (int)($res['cnt'] ?? 0);
    }
}
