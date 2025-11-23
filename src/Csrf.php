<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * Container-aware CSRF with AES-256-GCM and per-container isolation.
 *
 * Backwards compatibility:
 *  - generate()/validate()/regenerate()/getExpiresIn()/clear() continue to work
 *    and operate on the "default" container.
 *
 * Security:
 *  - Each container has its own session bucket, derived key (HKDF), optional pepper,
 *    and AES-GCM Additional Authenticated Data (AAD) binding.
 *  - Token payload binds to container id (cid), IP (optional), UA (optional), and iat.
 */
class Csrf
{
    /** Root session namespace for all CSRF state. */
    private string $sessionRoot = '_csrf_v2';

    /** Legacy single-key (kept for BC if someone clears manually). */
    private string $legacySessionKey = '_csrf_token';

    /** Master cipher key (32 bytes). */
    private string $cipherKey;

    /** Time-to-live (seconds). 0 means never expires. */
    private int $ttl;

    /** Last generated or validated payload. */
    private ?array $lastPayload = null;

    /**
     * Per-container runtime options.
     * Keys are container IDs, values are option arrays:
     *  - prefix  (string) : prefix added to session bucket key
     *  - bind_ip (bool)   : verify client IP (default: true)
     *  - bind_ua (bool)   : verify User-Agent (default: true)
     *  - pepper  (?string): optional per-container binary secret for HKDF salt
     * @var array<string, array{prefix:string,bind_ip:bool,bind_ua:bool,pepper:?string}>
     */
    private array $containerOptions = [];

    /** Provides client IP / User-Agent context. */
    private ClientContextProviderInterface $contextProvider;

    /**
     * @param string $cipherKey 32-byte key used for AES-256-GCM encryption.
     * @param int    $ttlSeconds Token TTL (seconds). 0 disables expiration.
     * @param ClientContextProviderInterface|null $contextProvider Optional client context provider (IP/UA).
     * @throws \InvalidArgumentException If $cipherKey length is not exactly 32 bytes.
     */
    public function __construct(
        string $cipherKey,
        int $ttlSeconds = 900,
        ?ClientContextProviderInterface $contextProvider = null
    ) {
        if (strlen($cipherKey) !== 32) {
            throw new \InvalidArgumentException('Cipher key must be exactly 32 bytes.');
        }
        $this->cipherKey = $cipherKey;
        $this->ttl = $ttlSeconds;
        $this->contextProvider = $contextProvider ?? new ServerGlobalClientContextProvider();
    }

    /**
     * Configure/override options for a container ID.
     *
     * @param string $containerId Container identifier (e.g., 'signup', 'profile').
     * @param array  $options     See $containerOptions description.
     * @return $this
     */
    public function withContainer(string $containerId, array $options): self
    {
        $defaults = [
            'prefix'  => '',
            'bind_ip' => true,
            'bind_ua' => true,
            'pepper'  => null,
        ];
        $this->containerOptions[$containerId] = array_replace($defaults, $options);
        return $this;
    }

    /** @return int TTL in seconds (0 means no expiry). */
    public function getTtl(): int
    {
        return $this->ttl;
    }

    /* ===================== Backwards-compatible API (default container) ===================== */

    /**
     * Generate an encrypted token for the default container.
     *
     * @param string|null $ip        Optional client IP override.
     * @param string|null $userAgent Optional User-Agent override.
     * @return string Encrypted token for the default container.
     */
    public function generate(?string $ip = null, ?string $userAgent = null): string
    {
        return $this->generateFor('default', $ip, $userAgent);
    }

    /**
     * Validate an encrypted token for the default container.
     *
     * @param string|null $encrypted Encrypted token.
     * @param string|null $ip        Optional client IP override.
     * @param string|null $userAgent Optional User-Agent override.
     * @return bool True if valid for the default container.
     */
    public function validate(?string $encrypted, ?string $ip = null, ?string $userAgent = null): bool
    {
        return $this->validateFor('default', $encrypted, $ip, $userAgent);
    }

    /** @return string New encrypted token for the default container. */
    public function regenerate(): string
    {
        return $this->regenerateFor('default');
    }

    /**
     * @return int|null Seconds until expiry of the default container token;
     *                  null if no token; 0 if expired; PHP_INT_MAX if TTL=0.
     */
    public function getExpiresIn(): ?int
    {
        return $this->getExpiresInFor('default');
    }

    /** @return array|null Last generated/validated payload. */
    public function getLastPayload(): ?array
    {
        return $this->lastPayload;
    }

    /** Clear the default container token state. */
    public function clear(): void
    {
        $this->clearFor('default');
    }

    /* ===================== Container-aware API ===================== */

    /**
     * Generate (or reuse unexpired) token for a container.
     *
     * @param string      $containerId Container identifier.
     * @param string|null $ip          Optional client IP override.
     * @param string|null $userAgent   Optional User-Agent override.
     * @return string Encrypted token.
     */
    public function generateFor(string $containerId, ?string $ip = null, ?string $userAgent = null): string
    {
        [$bucketKey, $cfg] = $this->resolveContainer($containerId);

        $state = $_SESSION[$this->sessionRoot][$bucketKey] ?? null;
        $hasState = is_array($state) && isset($state['token'], $state['iat'])
            && is_string($state['token']) && is_int($state['iat']);

        if (!$hasState || $this->isExpired($state)) {
            $state = [
                'token' => bin2hex(random_bytes(32)),
                'iat'   => time(),
            ];
            $_SESSION[$this->sessionRoot][$bucketKey] = $state;
        }

        $resolvedIp = $this->resolveIp($ip);
        $resolvedUa = $this->resolveUserAgent($userAgent);

        $payload = [
            'cid'   => $containerId,
            'token' => $state['token'],
            'ip'    => $cfg['bind_ip'] ? $resolvedIp : '',
            'ua'    => $cfg['bind_ua'] ? $resolvedUa : '',
            'iat'   => $state['iat'],
        ];

        $this->lastPayload = $payload;

        $derivedKey = $this->deriveContainerKey($containerId, $cfg['pepper']);
        $aad = $this->makeAad($containerId, $cfg['prefix']);
        return $this->encrypt($derivedKey, $payload, $aad);
    }

    /**
     * Validate an encrypted token for a specific container.
     *
     * @param string      $containerId Container identifier.
     * @param string|null $encrypted   Encrypted token to validate.
     * @param string|null $ip          Optional client IP override.
     * @param string|null $userAgent   Optional User-Agent override.
     * @return bool True on success, false otherwise.
     */
    public function validateFor(
        string $containerId,
        ?string $encrypted,
        ?string $ip = null,
        ?string $userAgent = null
    ): bool {
        if (!$encrypted) {
            return false;
        }

        [$bucketKey, $cfg] = $this->resolveContainer($containerId);

        $derivedKey = $this->deriveContainerKey($containerId, $cfg['pepper']);
        $aad = $this->makeAad($containerId, $cfg['prefix']);
        $payload = $this->decrypt($derivedKey, $encrypted, $aad);
        if (!$payload) {
            return false;
        }

        $this->lastPayload = $payload;

        if (($payload['cid'] ?? null) !== $containerId) {
            return false;
        }

        $state = $_SESSION[$this->sessionRoot][$bucketKey] ?? null;
        if (!is_array($state) || !isset($state['token'], $state['iat'])) {
            return false;
        }

        $reqIp = $this->resolveIp($ip);
        $reqUa = $this->resolveUserAgent($userAgent);
        $expIp = $cfg['bind_ip'] ? $reqIp : '';
        $expUa = $cfg['bind_ua'] ? $reqUa : '';

        if (
            $payload['token'] !== $state['token'] ||
            ($payload['ip'] ?? '') !== $expIp ||
            ($payload['ua'] ?? '') !== $expUa
        ) {
            return false;
        }

        if ($this->isExpired($state)) {
            return false;
        }

        $this->clearFor($containerId);
        return true;
    }

    /**
     * Validate a cached payload for a specific container (no decrypt).
     *
     * @param string      $containerId Container identifier.
     * @param array       $payload     Cached payload to check.
     * @param string|null $ip          Optional client IP override.
     * @param string|null $userAgent   Optional User-Agent override.
     * @return bool True if matches session and not expired.
     */
    public function validateCachedFor(
        string $containerId,
        array $payload,
        ?string $ip = null,
        ?string $userAgent = null
    ): bool {
        [$bucketKey, $cfg] = $this->resolveContainer($containerId);
        $this->lastPayload = $payload;

        $state = $_SESSION[$this->sessionRoot][$bucketKey] ?? null;
        if (!is_array($state) || !isset($state['token'], $state['iat'])) {
            return false;
        }

        $reqIp = $this->resolveIp($ip);
        $reqUa = $this->resolveUserAgent($userAgent);
        $expIp = $cfg['bind_ip'] ? $reqIp : '';
        $expUa = $cfg['bind_ua'] ? $reqUa : '';

        if (
            ($payload['cid'] ?? null) !== $containerId ||
            ($payload['token'] ?? null) !== $state['token'] ||
            ($payload['ip'] ?? '') !== $expIp ||
            ($payload['ua'] ?? '') !== $expUa
        ) {
            return false;
        }

        if ($this->isExpired($state)) {
            return false;
        }

        unset($_SESSION[$this->sessionRoot][$bucketKey]);
        return true;
    }

    /**
     * Force new token for a container (clears previous state).
     *
     * @param string $containerId
     * @return string New encrypted token.
     */
    public function regenerateFor(string $containerId): string
    {
        [$bucketKey] = $this->resolveContainer($containerId);
        unset($_SESSION[$this->sessionRoot][$bucketKey]);
        return $this->generateFor($containerId);
    }

    /**
     * Remaining lifetime for a container.
     *
     * @param string $containerId
     * @return int|null Seconds remaining, 0 if expired, null if no token, PHP_INT_MAX if TTL=0.
     */
    public function getExpiresInFor(string $containerId): ?int
    {
        [$bucketKey] = $this->resolveContainer($containerId);
        $state = $_SESSION[$this->sessionRoot][$bucketKey] ?? null;
        if (!is_array($state) || !isset($state['iat']) || !is_int($state['iat'])) {
            return null;
        }
        if ($this->ttl === 0) {
            return PHP_INT_MAX;
        }

        $elapsed = time() - $state['iat'];
        if ($elapsed >= $this->ttl) {
            return 0;
        }
        return $this->ttl - $elapsed;
    }

    /**
     * Clear token for a container.
     *
     * @param string $containerId
     * @return void
     */
    public function clearFor(string $containerId): void
    {
        [$bucketKey] = $this->resolveContainer($containerId);
        unset($_SESSION[$this->sessionRoot][$bucketKey]);
    }

    /* ===================== Internals ===================== */

    /**
     * Resolve session bucket and merged options for a container.
     *
     * @param string $containerId
     * @return array{0:string,1:array{prefix:string,bind_ip:bool,bind_ua:bool,pepper:?string}}
     */
    private function resolveContainer(string $containerId): array
    {
        $defaults = [
            'prefix'  => '',
            'bind_ip' => true,
            'bind_ua' => true,
            'pepper'  => null,
        ];
        $cfg = $this->containerOptions[$containerId] ?? $defaults;
        $bucketKey = ($cfg['prefix'] !== '' ? $cfg['prefix'] : '') . $containerId;

        if (!isset($_SESSION[$this->sessionRoot]) || !is_array($_SESSION[$this->sessionRoot])) {
            $_SESSION[$this->sessionRoot] = [];
        }

        return [$bucketKey, $cfg];
    }

    /**
     * Check if a given session state is expired.
     *
     * @param array|null $state
     * @return bool True if expired/invalid.
     */
    public function isExpired(?array $state): bool
    {
        if (!is_array($state) || !isset($state['iat']) || !is_int($state['iat'])) {
            return true;
        }
        if ($this->ttl === 0) {
            return false;
        }
        return (time() - $state['iat']) > $this->ttl;
    }

    /**
     * Resolve IP address using explicit override or context provider.
     *
     * @param string|null $override Explicit IP passed by caller (optional).
     * @return string Resolved IP address.
     */
    private function resolveIp(?string $override): string
    {
        if ($override !== null && $override !== '') {
            return $override;
        }
        return $this->contextProvider->getIp();
    }

    /**
     * Resolve User-Agent using explicit override or context provider.
     *
     * @param string|null $override Explicit User-Agent passed by caller (optional).
     * @return string Resolved User-Agent.
     */
    private function resolveUserAgent(?string $override): string
    {
        if ($override !== null && $override !== '') {
            return $override;
        }
        return $this->contextProvider->getUserAgent();
    }

    /**
     * Derive per-container 32-byte key with HKDF(SHA-256).
     *
     * @param string      $containerId
     * @param string|null $pepper Binary salt for HKDF-Extract; optional.
     * @return string 32-byte binary key.
     */
    private function deriveContainerKey(string $containerId, ?string $pepper): string
    {
        $salt = $pepper ?? '';
        $prk = hash_hmac('sha256', $this->cipherKey, $salt, true);
        $info = 'csrf:' . $containerId;
        $okm = '';
        $t = '';
        $len = 32;
        for ($i = 1; strlen($okm) < $len; $i++) {
            $t = hash_hmac('sha256', $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }
        return substr($okm, 0, 32);
    }

    /**
     * Build Additional Authenticated Data (AAD) for AES-GCM.
     *
     * @param string $containerId
     * @param string $prefix
     * @return string
     */
    private function makeAad(string $containerId, string $prefix): string
    {
        return 'cid=' . $containerId . ';prefix=' . $prefix;
    }

    /**
     * AES-256-GCM encrypt with AAD. Returns base64(iv|tag|ciphertext).
     *
     * @param string $key   32-byte binary key.
     * @param array  $data  Payload to encrypt.
     * @param string $aad   Additional authenticated data.
     * @return string Base64-encoded token.
     */
    private function encrypt(string $key, array $data, string $aad): string
    {
        $iv = random_bytes(12);
        $json = json_encode($data, JSON_UNESCAPED_SLASHES);
        $tag = '';

        $cipher = openssl_encrypt(
            $json,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
            16
        );

        return base64_encode($iv . $tag . $cipher);
    }

    /**
     * AES-256-GCM decrypt with AAD. Accepts base64(iv|tag|ciphertext).
     *
     * @param string $key   32-byte binary key.
     * @param string $input Base64 token.
     * @param string $aad   Additional authenticated data.
     * @return array|null Decrypted payload, or null on failure.
     */
    private function decrypt(string $key, string $input, string $aad): ?array
    {
        $raw = base64_decode($input, true);
        if ($raw === false || strlen($raw) < 28) {
            return null;
        }

        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ciphertext = substr($raw, 28);

        $json = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );

        if ($json === false) {
            return null;
        }

        return json_decode($json, true);
    }
}
