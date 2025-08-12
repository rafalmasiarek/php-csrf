<?php

namespace rafalmasiarek\Csrf;

use rafalmasiarek\Csrf\Csrf;

class CsrfCacheWrapper
{
    /**
     * @var EncryptedCsrfToken
     */
    // This class wraps the EncryptedCsrfToken to provide caching functionality.
    // It checks the cache first before validating the token, and stores the payload
    // in the cache if validation is successful and not in read-only mode.
    //
    private Csrf $core;

    /**
     * @var CsrfStorageInterface
     */
    // This interface defines the methods for storing and fetching CSRF tokens.
    // It is used to cache the CSRF tokens to avoid redundant validations.
    private CsrfStorageInterface $cache;

    /**
     * @var bool
     */
    // This flag indicates whether the wrapper is in read-only mode.
    // In read-only mode, it will not store any tokens in the cache.
    // This is useful for scenarios where you want to validate tokens without modifying the cache.
    // Defaults to false, meaning it will store tokens in the cache.
    // If set to true, it will only validate tokens without caching them.
    private bool $readOnly;

    /**
     * Constructor for the CsrfCacheWrapper.
     *
     * @param Csrf $core The core CSRF token handler.
     * @param CsrfStorageInterface $cache The storage interface for caching tokens.
     * @param bool $readOnly Whether to operate in read-only mode (default: false).
     */
    // Initializes the wrapper with the core CSRF token handler and the cache storage.
    // If readOnly is true, it will not store tokens in the cache.
    // This allows for flexibility in how the CSRF tokens are validated and cached.
    public function __construct(Csrf $core, CsrfStorageInterface $cache, bool $readOnly = false)
    {
        $this->core = $core;
        $this->cache = $cache;
        $this->readOnly = $readOnly;
    }


    /**
     * Generates a CSRF token and stores the payload in cache (if enabled).
     *
     * @return string The encrypted CSRF token.
     */
    // This method generates a CSRF token using the core CSRF token handler.
    // It retrieves the last payload from the core handler and stores it in the cache if not in read-only mode.
    // The generated token is then returned for use in forms or API requests.
    // This allows for efficient generation and caching of CSRF tokens, improving performance.
    // The token is encrypted and can be used to protect against CSRF attacks.
    // It ensures that the token is unique and securely stored.
    // This method is typically called when rendering a form or preparing an API request.
    // It is essential for generating secure tokens that can be validated later.
    // The cache is used to avoid redundant validations of the same token.
    public function generate(): string
    {
        $token = $this->core->generate();
        $payload = $this->core->getLastPayload();

        if (!$this->readOnly && $payload !== null) {
            $this->cache->store($token, $payload);
        }

        return $token;
    }

    /**
     * Validates a CSRF token.
     *
     * @param string $token The CSRF token to validate.
     * @return bool True if the token is valid, false otherwise.
     */
    // This method checks if the token is present in the cache.
    // If it is, it validates the cached payload.
    // If not, it validates the token using the core CSRF token handler.
    // If the validation is successful and not in read-only mode, it stores the payload in the cache.
    // Returns true if the token is valid, false otherwise.
    // This allows for efficient validation of CSRF tokens by leveraging caching.
    // It reduces the need for repeated validations of the same token, improving performance.
    public function validate(string $token): bool
    {
        $cached = $this->cache->fetch($token);

        if ($cached !== null) {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

            $isMatch =
                isset($cached['token'], $cached['ip'], $cached['ua'], $cached['iat']) &&
                $cached['ip'] === $ip &&
                $cached['ua'] === $ua &&
                !$this->core->isExpired($cached);

            if ($isMatch) {
                return true; // ✅ fast path — validated from cache
            }
        }

        // fallback to core decrypt/validate
        if (!$this->core->validate($token)) {
            return false;
        }

        if (!$this->readOnly) {
            $payload = $this->core->getLastPayload();
            if ($payload !== null) {
                $this->cache->store($token, $payload);
            }
        }

        return true;
    }
}
