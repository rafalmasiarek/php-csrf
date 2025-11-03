<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * In-memory array storage (useful for testing).
 */
class ArrayStorage implements CsrfStorageInterface
{
    /** @var array<string,array> */
    private array $data = [];

    public function store(string $encryptedToken, array $payload): void
    {
        $this->data[hash('sha256', $encryptedToken)] = $payload;
    }

    public function fetch(string $encryptedToken): ?array
    {
        $k = hash('sha256', $encryptedToken);
        return $this->data[$k] ?? null;
    }

    public function remove(string $encryptedToken): void
    {
        unset($this->data[hash('sha256', $encryptedToken)]);
    }
}
