<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

use PDO;

/**
 * MySQL-based implementation of CsrfStorageInterface.
 *
 * Schema (example):
 *   CREATE TABLE csrf_cache (
 *     token_hash VARCHAR(64) PRIMARY KEY,
 *     payload    JSON NOT NULL,
 *     created_at DATETIME NOT NULL
 *   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
 *
 * Notes:
 *   - We hash whatever key we get. For multi-container, pass a composite key
 *     like "<container>|<token>" to avoid cross-container collisions.
 */
class MysqlStorage implements CsrfStorageInterface
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /** @inheritDoc */
    public function store(string $key, array $payload): void
    {
        $stmt = $this->pdo->prepare(
            "REPLACE INTO csrf_cache (token_hash, payload, created_at) VALUES (?, ?, NOW())"
        );
        $stmt->execute([hash('sha256', $key), json_encode($payload, JSON_UNESCAPED_SLASHES)]);
    }

    /** @inheritDoc */
    public function fetch(string $key): ?array
    {
        $stmt = $this->pdo->prepare("SELECT payload FROM csrf_cache WHERE token_hash = ?");
        $stmt->execute([hash('sha256', $key)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? json_decode($row['payload'], true) : null;
    }

    /** @inheritDoc */
    public function remove(string $key): void
    {
        $stmt = $this->pdo->prepare("DELETE FROM csrf_cache WHERE token_hash = ?");
        $stmt->execute([hash('sha256', $key)]);
    }
}
