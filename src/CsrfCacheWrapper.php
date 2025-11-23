<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * Cache wrapper for CSRF validation.
 *
 * Caches decrypted payloads keyed by a composite "<container>|<token>" string.
 * On cache hit, validates IP/UA/TTL quickly without decryption.
 */
class CsrfCacheWrapper
{
    private Csrf $core;
    private CsrfStorageInterface $cache;
    private bool $readOnly;

    /**
     * Last cache debug info (for diagnostics only).
     *
     * Example structure:
     * [
     *   'op'        => 'generate'|'validate',
     *   'container' => 'default'|'<id>',
     *   'cache_key' => '<composite-key>',
     *   'hit'       => bool,        // validate only
     *   'fast_path' => bool,        // validate only (validateCachedFor() success)
     *   'stored'    => bool|null,   // whether payload was stored after core validate
     *   'result'    => bool|null,   // validate result
     *   'read_only' => bool,
     * ]
     *
     * @var array<string,mixed>|null
     */
    private ?array $lastCacheDebug = null;

    public function __construct(Csrf $core, CsrfStorageInterface $cache, bool $readOnly = false)
    {
        $this->core = $core;
        $this->cache = $cache;
        $this->readOnly = $readOnly;
    }

    /**
     * Return debug info for the last cache operation (generate/validate).
     *
     * @return array<string,mixed>|null
     */
    public function getLastCacheDebug(): ?array
    {
        return $this->lastCacheDebug;
    }

    /** Backwards-compat: default container. */
    public function generate(): string
    {
        return $this->generateFor('default');
    }

    /** Backwards-compat: default container. */
    public function validate(string $token): bool
    {
        return $this->validateFor('default', $token);
    }

    /**
     * Generate and cache for container.
     *
     * @param string $containerId
     * @return string
     */
    public function generateFor(string $containerId): string
    {
        $token    = $this->core->generateFor($containerId);
        $payload  = $this->core->getLastPayload();
        $cacheKey = $this->composeKey($containerId, $token);

        $stored = false;

        if (!$this->readOnly && $payload !== null) {
            $this->cache->store($cacheKey, $payload);
            $stored = true;
        }

        $this->lastCacheDebug = [
            'op'          => 'generate',
            'container'   => $containerId,
            'cache_key'   => $cacheKey,
            'stored'      => $stored,
            'read_only'   => $this->readOnly,
            'has_payload' => $payload !== null,
        ];

        return $token;
    }

    /**
     * Validate with cache fast-path for container.
     *
     * @param string $containerId
     * @param string $token
     * @return bool
     */
    public function validateFor(string $containerId, string $token): bool
    {
        $cacheKey = $this->composeKey($containerId, $token);

        $debug = [
            'op'        => 'validate',
            'container' => $containerId,
            'cache_key' => $cacheKey,
            'hit'       => false,
            'fast_path' => false,
            'stored'    => null,
            'result'    => null,
            'read_only' => $this->readOnly,
        ];

        $cached = $this->cache->fetch($cacheKey);

        if ($cached !== null) {
            $debug['hit'] = true;

            // Fast-path: let Csrf validate the cached payload (IP/UA/TTL/etc.),
            // without decrypting the token again.
            try {
                $fastOk = $this->core->validateCachedFor($containerId, $cached);
            } catch (\Throwable $e) {
                $fastOk = false;
                $debug['error'] = 'validateCachedFor_exception';
            }

            if (!empty($fastOk)) {
                $debug['fast_path'] = true;
                $debug['result']    = true;
                $this->lastCacheDebug = $debug;
                return true;
            }
        }

        // Cache miss or cached payload no longer valid – fallback to full validation.
        if (!$this->core->validateFor($containerId, $token)) {
            $debug['result'] = false;
            $this->lastCacheDebug = $debug;
            return false;
        }

        // Core validated successfully; optionally store fresh payload in cache.
        if (!$this->readOnly) {
            $payload = $this->core->getLastPayload();
            if ($payload !== null) {
                $this->cache->store($cacheKey, $payload);
                $debug['stored'] = true;
            } else {
                $debug['stored'] = false;
            }
        }

        $debug['result'] = true;
        $this->lastCacheDebug = $debug;

        return true;
    }

    /**
     * Remove a cached entry (optional helper).
     *
     * @param string $containerId
     * @param string $token
     * @return void
     */
    public function removeCached(string $containerId, string $token): void
    {
        $this->cache->remove($this->composeKey($containerId, $token));
    }

    /** Compose composite cache key. */
    private function composeKey(string $containerId, string $token): string
    {
        return $containerId . '|' . $token;
    }
}
