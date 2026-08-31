<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * Default client context provider that reads IP, User-Agent, and Origin from $_SERVER.
 *
 * Implements both ClientContextProviderInterface and OriginProviderInterface so that
 * origin-scope validation works out of the box without any extra configuration.
 *
 * @package rafalmasiarek\Csrf
 */
final class ServerGlobalClientContextProvider implements ClientContextProviderInterface, OriginProviderInterface
{
    /**
     * Returns the client IP address from REMOTE_ADDR.
     *
     * @return string IP address or empty string when unavailable.
     */
    public function getIp(): string
    {
        return isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])
            ? $_SERVER['REMOTE_ADDR']
            : '';
    }

    /**
     * Returns the HTTP User-Agent header value.
     *
     * @return string User-Agent string or empty string when unavailable.
     */
    public function getUserAgent(): string
    {
        return isset($_SERVER['HTTP_USER_AGENT']) && is_string($_SERVER['HTTP_USER_AGENT'])
            ? $_SERVER['HTTP_USER_AGENT']
            : '';
    }

    /**
     * Returns the effective HTTP Origin of the current request.
     *
     * Prefers the Origin header. Falls back to extracting scheme://host[:port]
     * from the Referer header when Origin is absent.
     *
     * @return string|null Normalised origin or null when neither header is present.
     */
    public function getOrigin(): ?string
    {
        if (isset($_SERVER['HTTP_ORIGIN']) && is_string($_SERVER['HTTP_ORIGIN']) && $_SERVER['HTTP_ORIGIN'] !== '') {
            return $_SERVER['HTTP_ORIGIN'];
        }

        if (isset($_SERVER['HTTP_REFERER']) && is_string($_SERVER['HTTP_REFERER']) && $_SERVER['HTTP_REFERER'] !== '') {
            $parts = parse_url($_SERVER['HTTP_REFERER']);
            if (!isset($parts['host'])) {
                return null;
            }

            $scheme = isset($parts['scheme']) ? $parts['scheme'] . '://' : '//';
            $port   = isset($parts['port']) ? ':' . $parts['port'] : '';

            return $scheme . $parts['host'] . $port;
        }

        return null;
    }
}
