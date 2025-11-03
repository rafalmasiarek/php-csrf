<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * File-based CsrfStorageInterface.
 * Stores entries under hashed filenames to avoid leaking token information.
 */
class FileStorage implements CsrfStorageInterface
{
    private string $dir;

    /**
     * @param string $dir Directory to store cache files (must be writable).
     */
    public function __construct(string $dir)
    {
        $this->dir = rtrim($dir, DIRECTORY_SEPARATOR);
        if (!is_dir($this->dir)) {
            if (!@mkdir($this->dir, 0775, true) && !is_dir($this->dir)) {
                throw new \RuntimeException('Failed to create directory: ' . $this->dir);
            }
        }
    }

    /** @inheritDoc */
    public function store(string $encryptedToken, array $payload): void
    {
        $path = $this->pathFor($encryptedToken);
        file_put_contents($path, json_encode($payload, JSON_UNESCAPED_SLASHES));
    }

    /** @inheritDoc */
    public function fetch(string $encryptedToken): ?array
    {
        $path = $this->pathFor($encryptedToken);
        if (!is_file($path)) {
            return null;
        }
        $json = file_get_contents($path);
        return $json ? json_decode($json, true) : null;
    }

    /** @inheritDoc */
    public function remove(string $encryptedToken): void
    {
        $path = $this->pathFor($encryptedToken);
        if (is_file($path)) {
            @unlink($path);
        }
    }

    private function pathFor(string $key): string
    {
        $hash = hash('sha256', $key);
        return $this->dir . DIRECTORY_SEPARATOR . $hash . '.json';
    }
}
