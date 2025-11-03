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
     * Render a hidden <input> with CSRF token for a given container.
     *
     * @param Csrf   $csrf
     * @param string $containerId Container name (default: "default").
     * @param string $inputName   Input field name (default: "_csrf").
     * @return string HTML string, already escaped.
     */
    public static function input(Csrf $csrf, string $containerId = 'default', string $inputName = '_csrf'): string
    {
        $token = $csrf->generateFor($containerId);
        $value = htmlspecialchars($token, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $name  = htmlspecialchars($inputName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        return sprintf('<input type="hidden" name="%s" value="%s">', $name, $value);
    }
}
