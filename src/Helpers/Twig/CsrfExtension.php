<?php
declare(strict_types=1);

namespace rafalmasiarek\Csrf\Helpers\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;
use rafalmasiarek\Csrf\Csrf;
use rafalmasiarek\Csrf\Helpers\HtmlHelper;

/**
 * Twig extension providing {{ csrf_field('container')|raw }}.
 */
final class CsrfExtension extends AbstractExtension
{
    private Csrf $csrf;
    private string $defaultContainer;
    private string $inputName;

    public function __construct(Csrf $csrf, string $defaultContainer = 'default', string $inputName = '_csrf')
    {
        $this->csrf = $csrf;
        $this->defaultContainer = $defaultContainer;
        $this->inputName = $inputName;
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('csrf_field', function (?string $container = null): string {
                return HtmlHelper::input($this->csrf, $container ?? $this->defaultContainer, $this->inputName);
            }),
        ];
    }
}
