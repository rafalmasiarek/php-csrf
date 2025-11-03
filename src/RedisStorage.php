<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * Redis-based CsrfStorageInterface.
 * Uses PHP Redis extension (\Redis) with simple set/get/del operations.
 */
class RedisStorage implements CsrfStorageInterface
{
    private \Redis $redis;
    private string $prefix;
    private int $ttl;

    /**
     * @param \Redis $redis Connected Redis client.
     * @param string  $prefix Key prefix (default: "csrf:").
     * @param int     $ttl    TTL for cache entries in seconds (default: 900).
     */
    public function __construct(\Redis $redis, string $prefix = 'csrf:', int $ttl = 900)
    {
        $this->redis = $redis;
        $this->prefix = $prefix;
        $this->ttl = $ttl;
    }

    /** @inheritDoc */
    public function store(string $key, array $payload): void
    {
        $redisKey = $this->prefix . hash('sha256', $key);
        $this->redis->set($redisKey, json_encode($payload, JSON_UNESCAPED_SLASHES), $this->ttl);
    }

    /** @inheritDoc */
    public function fetch(string $key): ?array
    {
        $redisKey = $this->prefix . hash('sha256', $key);
        $raw = $this->redis->get($redisKey);
        return $raw ? json_decode($raw, true) : null;
    }

    /** @inheritDoc */
    public function remove(string $key): void
    {
        $redisKey = $this->prefix . hash('sha256', $key);
        $this->redis->del($redisKey);
    }
}
