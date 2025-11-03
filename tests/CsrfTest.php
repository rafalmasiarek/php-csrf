<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use rafalmasiarek\Csrf\Csrf;

final class CsrfTest extends TestCase
{
    public function testGenerateAndValidateDefault(): void
    {
        $csrf = new Csrf(str_repeat('A', 32), 900);
        $token = $csrf->generate();
        $this->assertIsString($token);
        $this->assertTrue($csrf->validate($token));
    }

    public function testContainerIsolation(): void
    {
        $csrf = (new Csrf(str_repeat('B', 32), 900))
            ->withContainer('formA', [])
            ->withContainer('formB', []);

        $tokenA = $csrf->generateFor('formA');
        $this->assertTrue($csrf->validateFor('formA', $tokenA));
        $this->assertFalse($csrf->validateFor('formB', $tokenA));
    }

    public function testBindingsCanBeDisabled(): void
    {
        $csrf = (new Csrf(str_repeat('C', 32), 900))
            ->withContainer('loose', ['bind_ip' => false, 'bind_ua' => false]);

        $token = $csrf->generateFor('loose');
        $_SERVER['REMOTE_ADDR'] = '10.1.2.3';
        $_SERVER['HTTP_USER_AGENT'] = 'changed/ua';
        $this->assertTrue($csrf->validateFor('loose', $token));
    }

    public function testExpiration(): void
    {
        $csrf = new Csrf(str_repeat('D', 32), 1);
        $token = $csrf->generate();
        sleep(2);
        $this->assertFalse($csrf->validate($token));
    }
}
