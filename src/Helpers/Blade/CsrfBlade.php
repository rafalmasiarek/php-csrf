<?php
declare(strict_types=1);

namespace rafalmasiarek\Csrf\Helpers\Blade;

use rafalmasiarek\Csrf\Csrf;

/**
 * Blade helper for registering a @csrfField('container') directive.
 * Usage:
 *   \rafalmasiarek\Csrf\Helpers\Blade\CsrfBlade::register($bladeCompiler, $csrf);
 */
final class CsrfBlade
{
    /**
     * @param object $bladeCompiler Instance of Illuminate\View\Compilers\BladeCompiler.
     * @param Csrf   $csrf
     * @param string $defaultContainer
     * @param string $inputName
     */
    public static function register(object $bladeCompiler, Csrf $csrf, string $defaultContainer = 'default', string $inputName = '_csrf'): void
    {
        if (!method_exists($bladeCompiler, 'directive')) {
            throw new \InvalidArgumentException('Provided Blade compiler does not support directive()');
        }

        $bladeCompiler->directive('csrfField', function (?string $containerExpression = null) use ($csrf, $defaultContainer, $inputName) {
            // $containerExpression comes like: "'signup'" or null
            $code = <<<'PHP'
<?php
$__container = %s;
$__container = $__container === null ? %s : trim($__container, "'"");
$__token = (function($csrf, $container, $name) {
    return \rafalmasiarek\Csrf\Helpers\HtmlHelper::input($csrf, $container, $name);
})(app()->make(%s::class), $__container, %s);
echo $__token;
?>
PHP;
            return sprintf(
                $code,
                $containerExpression ?? 'null',
                var_export($defaultContainer, true),
                var_export(Csrf::class, true),
                var_export($inputName, true)
            );
        });
    }
}
