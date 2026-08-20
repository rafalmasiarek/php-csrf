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
     * @param Csrf   $csrf
     * @param string $containerId Container name (default: "default").
     * @param string $inputName   Input field name for the token (default: "_csrf").
     * @return string HTML string, already escaped.
     */
    public static function input(Csrf $csrf, string $containerId = 'default', string $inputName = '_csrf'): string
    {
        $token = $csrf->generateFor($containerId);
        $value = htmlspecialchars($token, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $name  = htmlspecialchars($inputName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        $field = sprintf('<input type="hidden" name="%s" value="%s">', $name, $value);

        if ($containerId !== 'default') {
            $safeId = htmlspecialchars($containerId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $field .= sprintf('<input type="hidden" name="_csrf_container" value="%s">', $safeId);
        }

        return $field;
    }
}
