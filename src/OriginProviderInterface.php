<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * Provides the HTTP Origin for CSRF origin-scope validation.
 *
 * Implement this interface alongside ClientContextProviderInterface to enable
 * per-container allowed_origins checks in Csrf::validateFor().
 * ServerGlobalClientContextProvider implements both interfaces by default.
 *
 * @package rafalmasiarek\Csrf
 */
interface OriginProviderInterface
{
    /**
     * Returns the effective HTTP Origin of the current request.
     *
     * Implementations should prefer the Origin header and fall back to
     * extracting scheme://host[:port] from the Referer header.
     * Return null when neither header is present.
     *
     * @return string|null Normalised origin (e.g. "https://example.com") or null.
     */
    public function getOrigin(): ?string;
}
