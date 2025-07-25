<?php

namespace rafalmasiarek\CsrfToken\Storage;

use Redis;

/**
 * RedisStorage is a Redis-based implementation of the CsrfStorageInterface.
 * It stores CSRF tokens and their associated payloads in Redis.
 */
class RedisStorage implements CsrfStorageInterface
{
    /**
     * @var Redis
     * The Redis instance used to interact with the Redis database.
     * It should be initialized with a valid connection to a Redis server.
     */
    private Redis $redis;

    /**
     * @var int
     * The time-to-live (TTL) for CSRF tokens in seconds.
     * Defaults to 900 seconds (15 minutes).
     */
    private int $ttl;

    /**
     * Constructor for the RedisStorage class.
     *
     * @param Redis $redis The Redis instance for database interactions.
     *                     It should be connected to a Redis server.
     * @param int $ttl The time-to-live (TTL) for CSRF tokens in seconds (default: 900).
     */
    public function __construct(Redis $redis, int $ttl = 900)
    {
        $this->redis = $redis;
        $this->ttl = $ttl;
    }

    /**
     * Store a CSRF token and its associated payload.
     *
     * @param string $key The CSRF token key (will be hashed).
     * @param array $payload The payload associated with the CSRF token.
     */
    // This method stores the CSRF token payload in Redis.
    // The key is prefixed with 'csrf:' and hashed using SHA-256 to ensure uniqueness.
    // The payload is encoded as JSON and stored with an expiration time defined by $ttl.
    // If a token with the same key already exists, it will be overwritten.
    // The TTL ensures that the token will be automatically removed after the specified time.
    // This method does not return any value.
    public function store(string $key, array $payload): void
    {
        $this->redis->setex('csrf:' . hash('sha256', $key), $this->ttl, json_encode($payload));
    }

    /**
     * Fetch the payload associated with a CSRF token.
     *
     * @param string $key The CSRF token key (will be hashed).
     * @return array|null The payload if found, null otherwise.
     */
    // This method retrieves the CSRF token payload from Redis.
    // It checks if the key exists in Redis, and if it does, it decodes the JSON content and returns it as an associative array.
    // If the key does not exist, it returns null.
    public function fetch(string $key): ?array
    {
        $raw = $this->redis->get('csrf:' . hash('sha256', $key));
        return $raw ? json_decode($raw, true) : null;
    }

    /**
     * Remove a CSRF token and its associated payload.
     *
     * @param string $key The CSRF token key (will be hashed).
     */
    // This method removes a CSRF token from Redis.
    public function remove(string $key): void
    {
        $this->redis->del(['csrf:' . hash('sha256', $key)]);
    }
}
