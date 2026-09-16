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
 *  - Token payload binds to container id (cid), IP (optional), UA (optional), origin (optional), and iat.
 *  - Optional per-container origin-scope: allowed_origins whitelist checked on validation.
 *    The origin is resolved automatically via the constructor's $originProvider (defaults to
 *    ServerGlobalClientContextProvider); pass an explicit $origin override to validateFor()
 *    otherwise.
 *  - Optional per-container origin binding: when container config 'origin' is set (non-null),
 *    that trusted origin is embedded in the payload at generation time and compared against
 *    the resolved request origin at validation time. This is independent from, and
 *    complementary to, the allowed_origins whitelist above.
 *  - Optional session-bound HMAC proof (_csrf_proof): issueFor() returns a CsrfPair
 *    (token + proof) where the proof is an HMAC-SHA256 over the exact opaque token,
 *    the container id, and a session-bound value (see SessionBindingProviderInterface),
 *    keyed by a key derived independently from the AES-GCM key (HKDF domain separation).
 *    The proof is transparent: passing it to validateFor()/validateCachedFor() always
 *    verifies it, while its absence is only rejected when the container config
 *    'require_proof' is true.
 */
class Csrf
{
    /** Maximum accepted length of a submitted _csrf_proof value, before any HMAC work. */
    private const MAX_PROOF_LENGTH = 128;

    /**
     * Built-in fallback values for any container option not supplied by
     * setDefaults() or withContainer(). Bottom layer of the 3-layer merge:
     * CONTAINER_OPTION_DEFAULTS < $defaults (setDefaults) < per-container options (withContainer).
     *
     * @var array{prefix:string,bind_ip:bool,bind_ua:bool,pepper:?string,allowed_origins:list<string>,origin_mode:string,origin:?string,require_proof:bool}
     */
    private const CONTAINER_OPTION_DEFAULTS = [
        'prefix'          => '',
        'bind_ip'         => true,
        'bind_ua'         => true,
        'pepper'          => null,
        'allowed_origins' => [],
        'origin_mode'     => 'lenient',
        'origin'          => null,
        'require_proof'   => false,
    ];

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
     *  - prefix          (string)        : prefix added to session bucket key
     *  - bind_ip         (bool)          : verify client IP (default: true)
     *  - bind_ua         (bool)          : verify User-Agent (default: true)
     *  - pepper          (?string)       : optional per-container binary secret for HKDF salt
     *  - allowed_origins (list<string>)  : origin whitelist; empty = no restriction
     *  - origin_mode     (string)        : 'lenient' (null origin passes) | 'strict' (null origin blocked)
     *  - origin          (?string)       : trusted origin; when non-null, it is embedded in the
     *                                      payload at generation and enforced against the request
     *                                      origin at validation (default: null = binding disabled)
     *  - require_proof   (bool)          : reject validation when _csrf_proof is missing (default: false)
     * @var array<string, array{prefix:string,bind_ip:bool,bind_ua:bool,pepper:?string,allowed_origins:list<string>,origin_mode:string,origin:?string,require_proof:bool}>
     */
    private array $containerOptions = [];

    /**
     * App-registered defaults, set once via setDefaults(). Applied to every
     * container beneath CONTAINER_OPTION_DEFAULTS and above per-container options.
     *
     * @var array<string, mixed>
     */
    private array $defaults = [];

    /** Provides client IP / User-Agent context. */
    private ClientContextProviderInterface $contextProvider;

    /** Provides the session-bound value used for _csrf_proof. */
    private SessionBindingProviderInterface $sessionBindingProvider;

    /** Provides the HTTP Origin for origin-scope validation and origin binding. */
    private OriginProviderInterface $originProvider;

    /**
     * @param string $cipherKey 32-byte key used for AES-256-GCM encryption.
     * @param int    $ttlSeconds Token TTL (seconds). 0 disables expiration.
     * @param ClientContextProviderInterface|null $contextProvider Optional client context provider (IP/UA).
     * @param SessionBindingProviderInterface|null $sessionBindingProvider Optional session binding
     *                                                                     provider for _csrf_proof
     *                                                                     (default: native PHP session id).
     * @param OriginProviderInterface|null $originProvider Optional origin provider. Defaults to
     *                                                      $contextProvider when it also implements
     *                                                      OriginProviderInterface, otherwise falls
     *                                                      back to ServerGlobalClientContextProvider.
     * @throws \InvalidArgumentException If $cipherKey length is not exactly 32 bytes.
     */
    public function __construct(
        string $cipherKey,
        int $ttlSeconds = 900,
        ?ClientContextProviderInterface $contextProvider = null,
        ?SessionBindingProviderInterface $sessionBindingProvider = null,
        ?OriginProviderInterface $originProvider = null
    ) {
        if (strlen($cipherKey) !== 32) {
            throw new \InvalidArgumentException('Cipher key must be exactly 32 bytes.');
        }
        $this->cipherKey = $cipherKey;
        $this->ttl = $ttlSeconds;
        $this->contextProvider = $contextProvider ?? new ServerGlobalClientContextProvider();
        $this->sessionBindingProvider = $sessionBindingProvider ?? new PhpSessionBindingProvider();
        $this->originProvider = $originProvider
            ?? ($this->contextProvider instanceof OriginProviderInterface
                ? $this->contextProvider
                : new ServerGlobalClientContextProvider());
    }

    /**
     * Configure/override options for a container ID.
     *
     * Merges, in order: built-in defaults < setDefaults() < $options.
     *
     * @param string $containerId Container identifier (e.g., 'signup', 'profile').
     * @param array  $options     See $containerOptions description.
     * @return $this
     */
    public function withContainer(string $containerId, array $options): self
    {
        $this->containerOptions[$containerId] = array_replace(
            self::CONTAINER_OPTION_DEFAULTS,
            $this->defaults,
            $options
        );
        return $this;
    }

    /**
     * Registers global default options applied to every container.
     *
     * Sits between the library's built-in fallback values and any per-container
     * options passed to withContainer(): CONTAINER_OPTION_DEFAULTS < $defaults < withContainer().
     * Also applies to container ids used without prior withContainer() registration
     * at all (e.g. ad-hoc container ids resolved at request time).
     *
     * @param array $defaults Same shape as withContainer()'s $options.
     * @return $this
     */
    public function setDefaults(array $defaults): self
    {
        $this->defaults = $defaults;
        return $this;
    }

    /**
     * Returns the fully-resolved effective configuration for a container id —
     * built-in defaults, app-registered defaults (setDefaults()), and any
     * per-container override (withContainer()), merged in that order. Works
     * even when the container was never explicitly registered.
     *
     * @param string $containerId
     * @return array{prefix:string,bind_ip:bool,bind_ua:bool,pepper:?string,allowed_origins:list<string>,origin_mode:string,origin:?string,require_proof:bool}
     */
    public function getContainerConfig(string $containerId): array
    {
        [, $cfg] = $this->resolveContainer($containerId);
        return $cfg;
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
     * @throws \RuntimeException If the container's 'origin' is set but does not normalize
     *                           to a valid http(s) origin.
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

        $boundOrigin = '';
        if ($cfg['origin'] !== null) {
            $boundOrigin = $this->normalizeOrigin($cfg['origin']);
            if ($boundOrigin === null) {
                throw new \RuntimeException(
                    "Container '{$containerId}' has an invalid 'origin' configured: '{$cfg['origin']}'."
                );
            }
        }

        $payload = [
            'cid'    => $containerId,
            'token'  => $state['token'],
            'ip'     => $cfg['bind_ip'] ? $resolvedIp : '',
            'ua'     => $cfg['bind_ua'] ? $resolvedUa : '',
            'iat'    => $state['iat'],
            'origin' => $boundOrigin,
        ];

        $this->lastPayload = $payload;

        $derivedKey = $this->deriveContainerKey($containerId, $cfg['pepper']);
        $aad = $this->makeAad($containerId, $cfg['prefix']);
        return $this->encrypt($derivedKey, $payload, $aad);
    }

    /**
     * Generate a token together with its session-bound _csrf_proof, atomically.
     *
     * Unlike generateFor(), the proof is always computed here regardless of the
     * container's 'require_proof' setting — that setting only controls whether
     * validateFor()/validateCachedFor() reject a request missing the proof.
     * Token and proof must always be refreshed together; never mix a token from
     * one pair with a proof from another.
     *
     * @param string      $containerId Container identifier.
     * @param string|null $ip          Optional client IP override.
     * @param string|null $userAgent   Optional User-Agent override.
     * @return CsrfPair Token and its matching proof (proof is null when the
     *                  session binding cannot be resolved, e.g. no active session).
     */
    public function issueFor(string $containerId, ?string $ip = null, ?string $userAgent = null): CsrfPair
    {
        $token = $this->generateFor($containerId, $ip, $userAgent);

        $sessionBinding = $this->sessionBindingProvider->getSessionBinding();
        if ($sessionBinding === '') {
            return new CsrfPair($token, null);
        }

        [, $cfg] = $this->resolveContainer($containerId);
        $proof = $this->generateProof($containerId, $token, $sessionBinding, $cfg['pepper']);
        return new CsrfPair($token, $proof);
    }

    /**
     * Validate an encrypted token for a specific container.
     *
     * @param string      $containerId Container identifier.
     * @param string|null $encrypted   Encrypted token to validate.
     * @param string|null $ip          Optional client IP override.
     * @param string|null $userAgent   Optional User-Agent override.
     * @param string|null $origin      Optional HTTP Origin override. When null, resolved
     *                                 automatically via OriginProviderInterface if available.
     * @param string|null $proof       Submitted _csrf_proof value. When present, it is always
     *                                 verified; when absent, it is only required if the
     *                                 container's 'require_proof' is true.
     * @return bool True on success, false otherwise.
     */
    public function validateFor(
        string $containerId,
        ?string $encrypted,
        ?string $ip = null,
        ?string $userAgent = null,
        ?string $origin = null,
        ?string $proof = null
    ): bool {
        if (!$encrypted) {
            return false;
        }

        [$bucketKey, $cfg] = $this->resolveContainer($containerId);

        if (!$this->checkProof($cfg, $containerId, $encrypted, $proof)) {
            return false;
        }

        if (!$this->checkOrigin($cfg, $origin)) {
            return false;
        }

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

        if (!$this->checkBoundOrigin($cfg, $payload, $origin)) {
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
     * @param string|null $origin      Optional HTTP Origin override.
     * @param string|null $rawToken    The exact opaque encrypted token this cached payload was
     *                                 looked up by. Required to verify $proof; when omitted and a
     *                                 proof is required or submitted, validation fails closed.
     * @param string|null $proof       Submitted _csrf_proof value (see validateFor()).
     * @return bool True if matches session and not expired.
     */
    public function validateCachedFor(
        string $containerId,
        array $payload,
        ?string $ip = null,
        ?string $userAgent = null,
        ?string $origin = null,
        ?string $rawToken = null,
        ?string $proof = null
    ): bool {
        [$bucketKey, $cfg] = $this->resolveContainer($containerId);

        if (!$this->checkProof($cfg, $containerId, $rawToken, $proof)) {
            return false;
        }

        if (!$this->checkOrigin($cfg, $origin)) {
            return false;
        }

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

        if (!$this->checkBoundOrigin($cfg, $payload, $origin)) {
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
        $cfg = $this->containerOptions[$containerId]
            ?? array_replace(self::CONTAINER_OPTION_DEFAULTS, $this->defaults);
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
     * Resolves the HTTP Origin for origin-scope validation.
     *
     * Uses the explicit $override when provided; falls back to $originProvider otherwise.
     *
     * @param string|null $override Explicit origin passed by the caller.
     *
     * @return string|null Resolved origin or null.
     */
    private function resolveOrigin(?string $override): ?string
    {
        if ($override !== null) {
            return $override;
        }
        return $this->originProvider->getOrigin();
    }

    /**
     * Checks the resolved origin against the container's allowed_origins list.
     *
     * Returns true immediately when allowed_origins is empty (no restriction).
     *
     * @param array       $cfg    Resolved container configuration.
     * @param string|null $origin Explicit origin override (null = auto-resolve).
     *
     * @return bool True when origin is permitted.
     */
    private function checkOrigin(array $cfg, ?string $origin): bool
    {
        $patterns = (array) ($cfg['allowed_origins'] ?? []);
        if ($patterns === []) {
            return true;
        }
        $mode     = (string) ($cfg['origin_mode'] ?? 'lenient');
        $resolved = $this->resolveOrigin($origin);
        return OriginMatcher::matches($resolved, $patterns, $mode);
    }

    /**
     * Verifies the payload's bound origin against the current request origin.
     *
     * No-op (returns true) when the container has no 'origin' configured.
     * When configured, both the stored and the resolved request origin must be
     * present, normalized, and equal (constant-time comparison); a missing
     * request origin is always rejected (strict fail-closed policy).
     *
     * @param array       $cfg     Resolved container configuration.
     * @param array       $payload Decrypted token payload.
     * @param string|null $origin  Explicit origin override (null = auto-resolve).
     *
     * @return bool True when the origin binding check passes.
     */
    private function checkBoundOrigin(array $cfg, array $payload, ?string $origin): bool
    {
        if ($cfg['origin'] === null) {
            return true;
        }

        $expected = (string) ($payload['origin'] ?? '');
        $actual   = $this->normalizeOrigin($this->resolveOrigin($origin));

        if ($expected === '' || $actual === null) {
            return false;
        }

        return hash_equals($expected, $actual);
    }

    /**
     * Verifies a submitted _csrf_proof value against the container configuration.
     *
     * Transparent by design: a submitted proof is always verified (rejecting the
     * request on mismatch), while a missing proof is only rejected when the
     * container's 'require_proof' is true. A proof cannot be verified without the
     * exact raw token it was issued for; passing $rawToken as null while a proof
     * is required or submitted fails closed.
     *
     * @param array       $cfg         Resolved container configuration.
     * @param string      $containerId Container identifier.
     * @param string|null $rawToken    Exact opaque _csrf token the proof was issued for.
     * @param string|null $proof       Submitted _csrf_proof value.
     *
     * @return bool True when the proof check passes.
     */
    private function checkProof(array $cfg, string $containerId, ?string $rawToken, ?string $proof): bool
    {
        if ($proof === null || $proof === '') {
            return !$cfg['require_proof'];
        }

        if (strlen($proof) > self::MAX_PROOF_LENGTH || $rawToken === null) {
            return false;
        }

        $sessionBinding = $this->sessionBindingProvider->getSessionBinding();
        if ($sessionBinding === '') {
            return false;
        }

        $expected = $this->generateProof($containerId, $rawToken, $sessionBinding, $cfg['pepper']);

        return hash_equals($expected, $proof);
    }

    /**
     * Computes the session-bound HMAC proof for a token.
     *
     * @param string      $containerId    Container identifier.
     * @param string      $csrfToken      The exact opaque encrypted _csrf token value.
     * @param string      $sessionBinding Current session-bound value (see SessionBindingProviderInterface).
     * @param string|null $pepper         Container's optional HKDF pepper (kept in sync with the
     *                                    encryption key derivation for the same container).
     *
     * @return string Base64URL-encoded (unpadded) HMAC-SHA256 proof.
     */
    private function generateProof(
        string $containerId,
        string $csrfToken,
        string $sessionBinding,
        ?string $pepper = null
    ): string {
        $proofKey = $this->deriveProofKey($containerId, $pepper);

        $message = $this->encodeProofFields([
            'csrf-proof-v1',
            $sessionBinding,
            $csrfToken,
            $containerId,
        ]);

        $mac = hash_hmac('sha256', $message, $proofKey, true);

        return rtrim(strtr(base64_encode($mac), '+/', '-_'), '=');
    }

    /**
     * Encodes proof fields unambiguously using 4-byte big-endian length prefixes.
     *
     * @param list<string> $fields Fields to encode, in order.
     *
     * @return string Encoded byte string.
     */
    private function encodeProofFields(array $fields): string
    {
        $output = '';
        foreach ($fields as $field) {
            $output .= pack('N', strlen($field)) . $field;
        }
        return $output;
    }

    /**
     * Normalizes an HTTP origin to scheme://host[:port] form.
     *
     * Lowercases scheme and host, strips a trailing slash, and omits the
     * port when it matches the scheme's default (443 for https, 80 for http).
     * Only http/https schemes are accepted; anything else (or malformed
     * input) normalizes to null.
     *
     * @param string|null $origin Raw origin value.
     *
     * @return string|null Normalized origin, or null when invalid/absent.
     */
    private function normalizeOrigin(?string $origin): ?string
    {
        if ($origin === null || $origin === '') {
            return null;
        }

        $parts = parse_url($origin);
        if (!isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return null;
        }

        $host = strtolower($parts['host']);
        $port = $parts['port'] ?? null;

        if (($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80)) {
            $port = null;
        }

        return $scheme . '://' . $host . ($port !== null ? ':' . $port : '');
    }

    /**
     * Derive the per-container 32-byte AES-GCM encryption key with HKDF(SHA-256).
     *
     * @param string      $containerId
     * @param string|null $pepper Binary salt for HKDF-Extract; optional.
     * @return string 32-byte binary key.
     */
    private function deriveContainerKey(string $containerId, ?string $pepper): string
    {
        return $this->deriveKey($containerId, $pepper, 'csrf');
    }

    /**
     * Derive the per-container 32-byte _csrf_proof HMAC key with HKDF(SHA-256).
     *
     * Uses a distinct HKDF info label from deriveContainerKey() so the proof key
     * is cryptographically independent from the AES-GCM encryption key even
     * though both are derived from the same master cipher key.
     *
     * @param string      $containerId
     * @param string|null $pepper Binary salt for HKDF-Extract; optional.
     * @return string 32-byte binary key.
     */
    private function deriveProofKey(string $containerId, ?string $pepper): string
    {
        return $this->deriveKey($containerId, $pepper, 'csrf-proof');
    }

    /**
     * Derive a purpose-scoped 32-byte key with HKDF(SHA-256).
     *
     * @param string      $containerId
     * @param string|null $pepper  Binary salt for HKDF-Extract; optional.
     * @param string      $purpose HKDF info label prefix providing domain separation
     *                             between different key purposes (e.g. 'csrf', 'csrf-proof').
     * @return string 32-byte binary key.
     */
    private function deriveKey(string $containerId, ?string $pepper, string $purpose): string
    {
        $salt = $pepper ?? '';
        $prk = hash_hmac('sha256', $this->cipherKey, $salt, true);
        $info = $purpose . ':' . $containerId;
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

    /**
     * Debug variant of container-aware validation.
     *
     * - Works for any container id (including "default").
     * - Does NOT clear the token on success.
     * - Never throws; always returns a detailed diagnostic array.
     *
     * Usage:
     *   $debug = $csrf->debugValidate($token);                          // default container
     *   $debug = $csrf->debugValidate($token, 'contactform_main');      // custom container
     *   $debug = $csrf->debugValidate($token, 'signup', $ip, $userAgent);
     *
     * Return structure:
     *  - ok          (bool)   : final validation result
     *  - reason      (?string): high-level reason (ok, missing_token, decrypt_failed, ...)
     *  - containerId (string) : container id used
     *  - input       (array)  : raw input info (encrypted_present, ip_param, ua_param)
     *  - steps       (array)  : list of completed steps
     *  - config      (array)  : effective container config (bind_ip, bind_ua, prefix, bucketKey, pepper_set)
     *  - payload_raw (array)  : decrypted payload (if decrypt succeeded)
     *  - state       (array)  : session state (token, iat) if present
     *  - expected    (array)  : expected token/ip/ua derived from state and config
     *  - actual      (array)  : actual token/ip/ua from payload
     *  - mismatch    (array)  : per-field match flags (only on payload_mismatch)
     *  - details     (array)  : extra details for some reasons (e.g. expired, container_mismatch)
     */
    public function debugValidate(
        ?string $encrypted,
        ?string $containerId = 'default',
        ?string $ip = null,
        ?string $userAgent = null,
        ?string $origin = null,
        ?string $proof = null
    ): array {
        $containerId = $containerId ?: 'default';

        $debug = [
            'ok'          => false,
            'reason'      => null,
            'containerId' => $containerId,
            'input'       => [
                'encrypted_present' => $encrypted !== null && $encrypted !== '',
                'ip_param'          => $ip,
                'ua_param'          => $userAgent,
                'origin_param'      => $origin,
                'proof_present'     => $proof !== null && $proof !== '',
            ],
            'steps'       => [],
        ];

        if (!$encrypted) {
            $debug['reason'] = 'missing_token';
            return $debug;
        }

        $debug['steps'][] = 'token_present';

        [$bucketKey, $cfg] = $this->resolveContainer($containerId);
        $debug['config'] = [
            'bucketKey'       => $bucketKey,
            'bind_ip'         => $cfg['bind_ip'],
            'bind_ua'         => $cfg['bind_ua'],
            'prefix'          => $cfg['prefix'],
            'pepper_set'      => $cfg['pepper'] !== null,
            'allowed_origins' => $cfg['allowed_origins'],
            'origin_mode'     => $cfg['origin_mode'],
            'origin'          => $cfg['origin'],
            'require_proof'   => $cfg['require_proof'],
        ];

        $proofOk = $this->checkProof($cfg, $containerId, $encrypted, $proof);
        $debug['proof'] = [
            'submitted' => $proof !== null && $proof !== '',
            'valid'     => $proofOk,
        ];
        if (!$proofOk) {
            $debug['reason'] = ($proof !== null && $proof !== '') ? 'proof_invalid' : 'proof_required_missing';
            return $debug;
        }
        $debug['steps'][] = 'proof_ok';

        $allowedOrigins = (array) ($cfg['allowed_origins'] ?? []);
        if ($allowedOrigins !== []) {
            $resolvedOrigin = $this->resolveOrigin($origin);
            $originMode     = (string) ($cfg['origin_mode'] ?? 'lenient');
            $originOk       = OriginMatcher::matches($resolvedOrigin, $allowedOrigins, $originMode);
            $debug['origin'] = [
                'resolved' => $resolvedOrigin,
                'mode'     => $originMode,
                'allowed'  => $originOk,
            ];
            if (!$originOk) {
                $debug['reason'] = 'origin_rejected';
                return $debug;
            }
            $debug['steps'][] = 'origin_ok';
        }

        $derivedKey = $this->deriveContainerKey($containerId, $cfg['pepper']);
        $aad        = $this->makeAad($containerId, $cfg['prefix']);
        $payload    = $this->decrypt($derivedKey, $encrypted, $aad);

        if (!$payload) {
            $debug['reason'] = 'decrypt_failed';
            return $debug;
        }

        $debug['steps'][]     = 'decrypt_ok';
        $debug['payload_raw'] = $payload;

        $this->lastPayload = $payload;

        if (($payload['cid'] ?? null) !== $containerId) {
            $debug['reason'] = 'container_mismatch';
            $debug['details'] = [
                'payload_cid' => $payload['cid'] ?? null,
            ];
            return $debug;
        }

        $debug['steps'][] = 'container_match';

        $state = $_SESSION[$this->sessionRoot][$bucketKey] ?? null;
        if (!is_array($state) || !isset($state['token'], $state['iat'])) {
            $debug['reason'] = 'missing_session_state';
            $debug['details'] = [
                'state' => $state,
            ];
            return $debug;
        }

        $debug['steps'][] = 'session_state_present';
        $debug['state']   = $state;

        $reqIp = $this->resolveIp($ip);
        $reqUa = $this->resolveUserAgent($userAgent);
        $expIp = $cfg['bind_ip'] ? $reqIp : '';
        $expUa = $cfg['bind_ua'] ? $reqUa : '';

        $debug['expected'] = [
            'token' => $state['token'],
            'ip'    => $expIp,
            'ua'    => $expUa,
        ];
        $debug['actual'] = [
            'token' => $payload['token'] ?? null,
            'ip'    => $payload['ip'] ?? null,
            'ua'    => $payload['ua'] ?? null,
        ];

        if (
            ($payload['token'] ?? null) !== $state['token'] ||
            ($payload['ip'] ?? '') !== $expIp ||
            ($payload['ua'] ?? '') !== $expUa
        ) {
            $debug['reason'] = 'payload_mismatch';
            $debug['mismatch'] = [
                'token_match' => ($payload['token'] ?? null) === $state['token'],
                'ip_match'    => ($payload['ip'] ?? '') === $expIp,
                'ua_match'    => ($payload['ua'] ?? '') === $expUa,
            ];
            return $debug;
        }

        if ($cfg['origin'] !== null) {
            $boundExpected = (string) ($payload['origin'] ?? '');
            $boundActual   = $this->normalizeOrigin($this->resolveOrigin($origin));
            $boundMatch = $boundExpected !== ''
                && $boundActual !== null
                && hash_equals($boundExpected, $boundActual);
            $debug['bound_origin'] = [
                'expected' => $boundExpected,
                'actual'   => $boundActual,
                'match'    => $boundMatch,
            ];
            if (!$debug['bound_origin']['match']) {
                $debug['reason'] = 'bound_origin_mismatch';
                return $debug;
            }
            $debug['steps'][] = 'bound_origin_ok';
        }

        if ($this->isExpired($state)) {
            $debug['reason']  = 'expired';
            $debug['details'] = [
                'iat' => $state['iat'] ?? null,
                'now' => time(),
                'ttl' => $this->ttl,
            ];
            return $debug;
        }

        // IMPORTANT: do NOT clear the token here – this is debug-only.
        $debug['ok']     = true;
        $debug['reason'] = 'ok';

        return $debug;
    }
}
