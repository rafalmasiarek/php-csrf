<?php

namespace rafalmasiarek\CsrfToken;

class EncryptedCsrfToken
{
    /**
     * @var string
     */
    // This is the session key used to store the CSRF token in the session.
    // It is used to retrieve the token during validation.
    private string $sessionKey = '_csrf_token';

    /**
     * @var string
     */
    // This is the cipher key used for encrypting and decrypting the CSRF token payload.
    // It must be exactly 32 bytes long for AES-256-GCM encryption.
    // It is used to ensure the security of the CSRF token.
    private string $cipherKey;

    /**
     * @var int
     */
    // This is the time-to-live (TTL) for the CSRF token in seconds.
    // It defines how long the token is valid before it expires.
    // The default value is set to 900 seconds (15 minutes).
    // It is used to prevent replay attacks by ensuring that old tokens cannot be reused.
    // If the token is not used within this time frame, it will be considered invalid.
    // It is used to enhance security by limiting the lifetime of the token.
    // It can be adjusted based on the application's security requirements.
    // For example, if the application requires a shorter validity period for security reasons,
    // this value can be set to a lower number.
    // Conversely, if the application needs a longer validity period for usability reasons,
    // this value can be increased.
    // The TTL is checked during validation to ensure that the token is still valid.
    // If the current time exceeds the token's issue time plus the TTL, the token is considered expired.
    // This helps to mitigate the risk of CSRF attacks by ensuring that tokens cannot be reused indefinitely.
    // It is a crucial part of the CSRF token's security mechanism.
    private int $ttl;

    /**
     * @var array|null
     */
    // This property holds the last payload that was generated or validated.
    // It is used to store the token, IP address, user agent, and issue time.
    // It is useful for debugging and logging purposes, allowing developers to inspect the last used CSRF token payload.
    // It is set when a new token is generated or when a token is validated.
    // It can be accessed using the getLastPayload() method.
    // It is nullable, meaning it can be null if no token has been generated or validated yet.
    // This allows the application to check if a token has been used before attempting to validate it.
    // If no token has been generated or validated, this property will be null.
    // It is not stored in the session or any persistent storage, but only in memory during
    // the lifetime of the EncryptedCsrfToken instance.
    // This property is useful for applications that need to log or debug CSRF token usage.
    private ?array $lastPayload = null;

    /**
     * Constructor for the EncryptedCsrfToken.
     *
     * @param string $cipherKey The key used for AES-256-GCM encryption (must be 32 bytes).
     * @param int $ttlSeconds The time-to-live for the token in seconds (default: 900).
     * @throws \InvalidArgumentException if the cipher key is not exactly 32 bytes.
     */
    // Initializes the EncryptedCsrfToken instance with a cipher key and an optional TTL.
    public function __construct(string $cipherKey, int $ttlSeconds = 900)
    {
        if (strlen($cipherKey) !== 32) {
            throw new \InvalidArgumentException('Cipher key must be exactly 32 bytes.');
        }
        $this->cipherKey = $cipherKey;
        $this->ttl = $ttlSeconds;
    }

    /**
     * Generates a new CSRF token.
     *
     * @return string The encrypted CSRF token.
     */
    // This method generates a new CSRF token, encrypts it, and stores it in the session.
    // It also includes the current IP address, user agent, and issue time in the payload.
    // The generated token is a random 32-byte hexadecimal string.
    // The payload is then encrypted using AES-256-GCM with the provided cipher key.
    // The encrypted token is returned as a base64-encoded string.
    // This token can be used in forms or AJAX requests to protect against CSRF attacks.
    // The session key is used to store the token in the user's session, allowing it to
    // be validated later when the form is submitted or the AJAX request is made.
    // The token is valid for the duration specified by the TTL (time-to-live).
    // The payload includes the token, the user's IP address, user agent, and the issue time.
    // This information is used during validation to ensure that the token is still valid
    // and has not been tampered with.  
    public function generate(): string
    {
        $token = bin2hex(random_bytes(32));
        $_SESSION[$this->sessionKey] = $token;

        $payload = [
            'token' => $token,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'iat' => time(),
        ];

        $this->lastPayload = $payload;
        return $this->encrypt($payload);
    }

    /**
     * Validates a CSRF token.
     *
     * @param string|null $encrypted The encrypted CSRF token to validate.
     * @return bool True if the token is valid, false otherwise.
     */
    // This method validates the provided encrypted CSRF token.
    // It decrypts the token, checks if it matches the session token,
    // and verifies the IP address, user agent, and issue time.
    // If the token is valid, it updates the lastPayload property with the decrypted payload.
    // It returns true if the token is valid and has not expired, false otherwise.
    // The validation checks include:
    // - The token matches the one stored in the session.
    // - The IP address matches the one from the request.
    // - The user agent matches the one from the request.
    // - The issue time is within the allowed TTL (time-to-live).
    // If any of these checks fail, the token is considered invalid.
    // If the token is valid, it can be used to protect against CSRF attacks.
    // This method is typically called when processing a form submission or an AJAX request
    // to ensure that the request is legitimate and not a CSRF attack.
    // It is important to call this method before processing any sensitive actions
    // that require CSRF protection, such as modifying user data or performing actions
    // that could affect the state of the application.
    public function validate(?string $encrypted): bool
    {
        if (!$encrypted) return false;
        $payload = $this->decrypt($encrypted);
        if (!$payload) return false;

        $this->lastPayload = $payload;

        if (
            $payload['token'] !== ($_SESSION[$this->sessionKey] ?? null) ||
            $payload['ip'] !== ($_SERVER['REMOTE_ADDR'] ?? '') ||
            $payload['ua'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')
        ) {
            return false;
        }

        if (time() - $payload['iat'] > $this->ttl) {
            return false;
        }

        return true;
    }

    /**
     * Validates a cached CSRF token payload.
     *
     * @param array $payload The payload to validate.
     * @return bool True if the payload is valid, false otherwise.
     */
    // This method validates a cached CSRF token payload.
    // It checks if the payload matches the session token, IP address, user agent,
    // and issue time. It also checks if the token has not expired based on the TTL
    // (time-to-live).
    // It is used to validate tokens that have been previously cached, allowing for
    // efficient validation without needing to decrypt the token again.
    // The payload should contain the following keys:
    // - 'token': The CSRF token.
    // - 'ip': The user's IP address.
    // - 'ua': The user's user agent.
    // - 'iat': The issue time of the token.
    // If the payload is valid, it updates the lastPayload property with the provided payload.
    // It returns true if the payload is valid and has not expired, false otherwise.
    // This method is useful in scenarios where the CSRF token has been cached
    // and needs to be validated without going through the decryption process again.
    // It can be used in conjunction with a caching mechanism to improve performance
    // by avoiding repeated decryption of the same token.
    // It is typically called when the application needs to validate a CSRF token
    // that has been previously generated and cached, such as when processing a form submission
    // or an AJAX request that includes the CSRF token in the payload.  
    public function validateCached(array $payload): bool
    {
        $this->lastPayload = $payload;

        if (
            $payload['token'] !== ($_SESSION[$this->sessionKey] ?? null) ||
            $payload['ip'] !== ($_SERVER['REMOTE_ADDR'] ?? '') ||
            $payload['ua'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')
        ) {
            return false;
        }

        if (time() - $payload['iat'] > $this->ttl) {
            return false;
        }

        return true;
    }

    /**
     * Retrieves the last payload used for the CSRF token.
     *
     * @return array|null The last payload, or null if no payload has been set.
     */
    // This method returns the last payload that was generated or validated.
    // It can be used to inspect the details of the last CSRF token used,
    // including the token, IP address, user agent, and issue time.
    // This is useful for debugging and logging purposes, allowing developers to
    // see the last used CSRF token payload.
    // It returns null if no payload has been set, which can happen if no token has
    // been generated or validated yet.
    public function getLastPayload(): ?array
    {
        return $this->lastPayload;
    }

    /**
     * Clears the CSRF token from the session.
     *
     * @return void
     */
    // This method clears the CSRF token from the session.
    // It removes the token stored under the session key, effectively invalidating it.
    // This is useful when you want to reset the CSRF token, for example, after
    // a successful form submission or when the user logs out.
    // After calling this method, a new CSRF token will need to be generated
    // for subsequent requests that require CSRF protection.
    public function clear(): void
    {
        unset($_SESSION[$this->sessionKey]);
    }

    /**
     * Encrypts the CSRF token payload.
     *
     * @param array $data The payload data to encrypt.
     * @return string The base64-encoded encrypted token.
     */
    // This method encrypts the provided payload data using AES-256-GCM encryption.
    // It generates a random initialization vector (IV) and uses the cipher key
    // to encrypt the JSON-encoded payload. The IV and authentication tag are prepended
    // to the encrypted data, and the result is base64-encoded for easy storage and
    // transmission.
    private function encrypt(array $data): string
    {
        $iv = random_bytes(12);
        $json = json_encode($data);
        $tag = '';

        $cipher = openssl_encrypt(
            $json,
            'aes-256-gcm',
            $this->cipherKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return base64_encode($iv . $tag . $cipher);
    }

    /**
     * Decrypts the CSRF token payload.
     *
     * @param string $input The base64-encoded encrypted token.
     * @return array|null The decrypted payload, or null if decryption fails.
     */
    // This method decrypts the provided base64-encoded encrypted token.
    // It decodes the input, extracts the IV, authentication tag, and ciphertext,
    // and then uses the cipher key to decrypt the data using AES-256-GCM.
    // If decryption is successful, it returns the decoded JSON payload as an associative array.
    // If decryption fails or the input is invalid, it returns null.
    // The method expects the input to be a base64-encoded string that contains
    // the IV, tag, and ciphertext concatenated together.
    // The IV is the first 12 bytes, the tag is the next 16 bytes,
    // and the ciphertext is the remaining bytes.
    // This method is used to retrieve the original payload data from the encrypted token,
    // allowing the application to validate the CSRF token and its associated data.
    private function decrypt(string $input): ?array
    {
        $raw = base64_decode($input);
        if ($raw === false || strlen($raw) < 28) return null;

        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ciphertext = substr($raw, 28);

        $json = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $this->cipherKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($json === false) return null;

        return json_decode($json, true);
    }
}
