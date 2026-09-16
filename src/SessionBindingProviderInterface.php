<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * Provides a value that changes with every authenticated session, used to
 * bind the _csrf_proof HMAC to the current login/session context.
 *
 * Implementations must never return a static account identifier (user id,
 * email, username) — the returned value must change whenever the login
 * session is regenerated (e.g. on login, privilege elevation, or logout).
 *
 * @package rafalmasiarek\Csrf
 */
interface SessionBindingProviderInterface
{
    /**
     * Returns the current session-bound value used as HMAC proof input.
     *
     * The value is only ever used as an HMAC input and is never exposed in
     * plaintext inside the _csrf_proof value.
     *
     * @return string Opaque, session-dependent binding value.
     */
    public function getSessionBinding(): string;
}
