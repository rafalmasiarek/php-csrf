<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * Default session binding provider backed by the native PHP session id.
 *
 * Suitable when the application relies on native PHP sessions for
 * authentication. Applications that decouple their logical login session
 * from the PHP session id (e.g. JWT-backed sessions) should provide a
 * custom SessionBindingProviderInterface implementation instead.
 *
 * @package rafalmasiarek\Csrf
 */
final class PhpSessionBindingProvider implements SessionBindingProviderInterface
{
    /**
     * Returns the current native PHP session id.
     *
     * @return string Session id (empty string when no session is active).
     */
    public function getSessionBinding(): string
    {
        return session_id() ?: '';
    }
}
