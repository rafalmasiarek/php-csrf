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

    public function __construct(Csrf $core, CsrfStorageInterface $cache, bool $readOnly = false)
    {
        $this->core = $core;
        $this->cache = $cache;
        $this->readOnly = $readOnly;
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
        $token = $this->core->generateFor($containerId);
        $payload = $this->core->getLastPayload();

        if (!$this->readOnly && $payload !== null) {
            $this->cache->store($this->composeKey($containerId, $token), $payload);
        }

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
        $cached = $this->cache->fetch($cacheKey);

        if ($cached !== null) {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

            $bindIp = ($cached['ip'] ?? '') !== '';
            $bindUa = ($cached['ua'] ?? '') !== '';

            $isMatch =
                isset($cached['cid'], $cached['token'], $cached['iat']) &&
                $cached['cid'] === $containerId &&
                (!$bindIp || $cached['ip'] === $ip) &&
                (!$bindUa || $cached['ua'] === $ua) &&
                !$this->core->isExpired(['iat' => $cached['iat']]);

            if ($isMatch) {
                return true;
            }
        }

        if (!$this->core->validateFor($containerId, $token)) {
            return false;
        }

        if (!$this->readOnly) {
            $payload = $this->core->getLastPayload();
            if ($payload !== null) {
                $this->cache->store($cacheKey, $payload);
            }
        }

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
