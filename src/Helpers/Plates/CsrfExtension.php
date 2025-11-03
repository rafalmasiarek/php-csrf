<?php
declare(strict_types=1);

namespace rafalmasiarek\Csrf\Helpers\Plates;

use League\Plates\Engine;
use rafalmasiarek\Csrf\Csrf;
use rafalmasiarek\Csrf\Helpers\HtmlHelper;

/**
 * Plates extension to expose csrf_field() function.
 */
final class CsrfExtension
{
    public static function register(Engine $engine, Csrf $csrf, string $defaultContainer = 'default', string $inputName = '_csrf'): void
    {
        $engine->registerFunction('csrf_field', function (?string $container = null) use ($csrf, $defaultContainer, $inputName) {
            return HtmlHelper::input($csrf, $container ?? $defaultContainer, $inputName);
        });
    }
}
