<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use rafalmasiarek\Csrf\Csrf;
use rafalmasiarek\Csrf\ClientContextProviderInterface;

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

    public function testCustomClientContextProviderIsUsed(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.10';
        $_SERVER['HTTP_USER_AGENT'] = 'custom-test-agent/1.0';

        $provider = new class implements ClientContextProviderInterface {
            public function getIp(): string
            {
                return '203.0.113.10';
            }

            public function getUserAgent(): string
            {
                return 'custom-test-agent/1.0';
            }
        };

        $csrf = new Csrf(str_repeat('E', 32), 900, $provider);

        $token = $csrf->generate();
        $this->assertIsString($token);

        $this->assertTrue($csrf->validate($token));

        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
        $_SERVER['HTTP_USER_AGENT'] = 'different/ua';

        $this->assertFalse($csrf->validate($token));
    }
}
