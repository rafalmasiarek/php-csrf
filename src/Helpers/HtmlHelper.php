<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf\Helpers;

use rafalmasiarek\Csrf\Csrf;

/**
 * Generic HTML helper for rendering CSRF inputs.
 */
final class HtmlHelper
{
    /**
     * Render hidden inputs for CSRF protection.
     *
     * When a non-default container is used, emits a second hidden input
     * (_csrf_container) so the server-side middleware knows which container
     * to validate against. Without it, the middleware falls back to the
     * "default" container and validation always fails for named containers.
     *
     * Transparently issues the token together with its _csrf_proof (see
     * Csrf::issueFor()) and emits a third hidden input (_csrf_proof) whenever
     * a proof is available (i.e. a session is active). No template changes
     * are required to start benefiting from it; it has no effect on
     * validation unless the receiving container sets 'require_proof'.
     *
     * @param Csrf        $csrf
     * @param string      $containerId Container name (default: "default").
     * @param string      $inputName   Input field name for the token (default: "_csrf").
     * @param string|null $ip          Optional client IP override. Pass this whenever the
     *                                 caller already resolves the real client IP itself (e.g.
     *                                 behind a trusted proxy/CDN) — otherwise bind_ip validates
     *                                 against the proxy's address instead of the visitor's, and
     *                                 a validateFor() call that does pass the real IP will never
     *                                 match a token issued without it.
     * @param string|null $userAgent   Optional User-Agent override.
     * @return string HTML string, already escaped.
     */
    public static function input(
        Csrf $csrf,
        string $containerId = 'default',
        string $inputName = '_csrf',
        ?string $ip = null,
        ?string $userAgent = null
    ): string {
        $pair  = $csrf->issueFor($containerId, $ip, $userAgent);
        $value = htmlspecialchars($pair->token, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $name  = htmlspecialchars($inputName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        $field = sprintf('<input type="hidden" name="%s" value="%s">', $name, $value);

        if ($containerId !== 'default') {
            $safeId = htmlspecialchars($containerId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $field .= sprintf('<input type="hidden" name="_csrf_container" value="%s">', $safeId);
        }

        if ($pair->proof !== null) {
            $safeProof = htmlspecialchars($pair->proof, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $field .= sprintf('<input type="hidden" name="_csrf_proof" value="%s">', $safeProof);
        }

        return $field;
    }

    /**
     * Returns the raw encrypted CSRF token value for a container, without
     * wrapping it in an HTML input (e.g. for embedding in a <meta> tag or
     * passing to client-side JavaScript). Does not compute or expose a proof.
     *
     * @param Csrf        $csrf
     * @param string      $containerId Container name (default: "default").
     * @param string|null $ip          Optional client IP override (see input()).
     * @param string|null $userAgent   Optional User-Agent override.
     * @return string Encrypted token value (not HTML-escaped).
     */
    public static function token(
        Csrf $csrf,
        string $containerId = 'default',
        ?string $ip = null,
        ?string $userAgent = null
    ): string {
        return $csrf->generateFor($containerId, $ip, $userAgent);
    }
}
