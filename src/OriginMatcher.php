<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * Matches an HTTP Origin value against a list of allowed patterns.
 *
 * Pattern syntax:
 *  - Full origin  : "https://example.com"  — scheme + host must match exactly.
 *  - Scheme-free  : "example.com"          — only host[:port] is compared;
 *                                            any scheme is accepted.
 *  - Wildcard     : "https://*.example.com" or "*.example.com"
 *                   Each * matches exactly one subdomain label (no dots).
 *                   "https://*.example.com" matches "https://www.example.com"
 *                   but NOT "https://a.b.example.com".
 *
 * @package rafalmasiarek\Csrf
 */
final class OriginMatcher
{
    /**
     * Checks whether $origin is permitted by $patterns under the given $mode.
     *
     * @param string|null  $origin   Actual origin from the request (may be null when
     *                               the browser did not send an Origin/Referer header).
     * @param list<string> $patterns Allowed origin patterns (empty = no restriction).
     * @param string       $mode     'strict' — null origin is rejected.
     *                               'lenient' — null origin is accepted (default).
     *
     * @return bool True when the origin is permitted.
     */
    public static function matches(?string $origin, array $patterns, string $mode = 'lenient'): bool
    {
        if ($patterns === []) {
            return true;
        }

        if ($origin === null) {
            return $mode !== 'strict';
        }

        foreach ($patterns as $pattern) {
            if (self::patternMatches((string) $pattern, $origin)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Tests a single pattern against the actual origin.
     *
     * @param string $pattern Allowed-origin pattern (may include * and optional scheme).
     * @param string $origin  Actual request origin.
     *
     * @return bool
     */
    private static function patternMatches(string $pattern, string $origin): bool
    {
        $schemeInPattern = str_contains($pattern, '://');

        if ($schemeInPattern) {
            $subject = $origin;
        } else {
            // Strip scheme from actual origin before comparing.
            $subject = (string) preg_replace('#^[a-zA-Z][a-zA-Z0-9+\-.]*://#', '', $origin);
        }

        if (!str_contains($pattern, '*')) {
            return strcasecmp($subject, $pattern) === 0;
        }

        $regex = self::patternToRegex($pattern);

        return (bool) preg_match($regex, $subject);
    }

    /**
     * Converts a wildcard origin pattern to a PCRE regex.
     *
     * Each * is expanded to [^.]+ (one subdomain label, no dots).
     *
     * @param string $pattern Origin pattern potentially containing *.
     *
     * @return string PCRE regex with delimiters.
     */
    private static function patternToRegex(string $pattern): string
    {
        $escaped = preg_quote($pattern, '#');
        $regex   = str_replace('\*', '[^.]+', $escaped);

        return '#^' . $regex . '$#i';
    }
}
