<?php

namespace rafalmasiarek\Csrf;

interface CsrfStorageInterface
{
    /**
     * Store a CSRF token and its associated payload.
     *
     * @param string $encryptedToken The encrypted CSRF token.
     * @param array $payload The payload associated with the CSRF token.
     */
    public function store(string $encryptedToken, array $payload): void;

    /**
     * Fetch the payload associated with a CSRF token.
     *
     * @param string $encryptedToken The encrypted CSRF token.
     * @return array|null The payload if found, null otherwise.
     */
    public function fetch(string $encryptedToken): ?array;

    /**
     * Remove a CSRF token and its associated payload.
     *
     * @param string $encryptedToken The encrypted CSRF token to remove.
     */
    public function remove(string $encryptedToken): void;
}
