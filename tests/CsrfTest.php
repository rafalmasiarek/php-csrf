<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use rafalmasiarek\Csrf\Csrf;
use rafalmasiarek\Csrf\ClientContextProviderInterface;
use rafalmasiarek\Csrf\OriginMatcher;

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

    /* ===================== OriginMatcher unit tests ===================== */

    /**
     * Exact full-origin match (scheme + host) passes when origin matches the pattern.
     */
    public function testOriginMatcherExactWithScheme(): void
    {
        $this->assertTrue(OriginMatcher::matches('https://example.com', ['https://example.com']));
    }

    /**
     * Scheme mismatch is rejected when the pattern includes a scheme.
     */
    public function testOriginMatcherExactSchemeMismatchRejected(): void
    {
        $this->assertFalse(OriginMatcher::matches('http://example.com', ['https://example.com']));
    }

    /**
     * Scheme-free pattern accepts any scheme.
     */
    public function testOriginMatcherSchemeFreePasses(): void
    {
        $this->assertTrue(OriginMatcher::matches('https://example.com', ['example.com']));
        $this->assertTrue(OriginMatcher::matches('http://example.com', ['example.com']));
    }

    /**
     * Wildcard matches exactly one subdomain label.
     */
    public function testOriginMatcherWildcardSingleLabel(): void
    {
        $this->assertTrue(OriginMatcher::matches('https://www.example.com', ['*.example.com']));
        $this->assertFalse(
            OriginMatcher::matches('https://a.b.example.com', ['*.example.com']),
            'Wildcard must not span multiple labels'
        );
    }

    /**
     * Empty patterns list permits all origins.
     */
    public function testOriginMatcherEmptyPatternsPermitsAll(): void
    {
        $this->assertTrue(OriginMatcher::matches(null, []));
        $this->assertTrue(OriginMatcher::matches('https://anywhere.example.com', []));
    }

    /**
     * Strict mode rejects null origin.
     */
    public function testOriginMatcherStrictBlocksNullOrigin(): void
    {
        $this->assertFalse(OriginMatcher::matches(null, ['https://example.com'], 'strict'));
    }

    /**
     * Lenient mode (default) accepts null origin.
     */
    public function testOriginMatcherLenientAllowsNullOrigin(): void
    {
        $this->assertTrue(OriginMatcher::matches(null, ['https://example.com'], 'lenient'));
        $this->assertTrue(OriginMatcher::matches(null, ['https://example.com']));
    }

    /* ===================== Csrf origin-scope integration tests ===================== */

    /**
     * Token validates when the passed origin matches the container whitelist.
     */
    public function testOriginScopeAllowsMatchingOrigin(): void
    {
        $csrf = (new Csrf(str_repeat('F', 32), 900))
            ->withContainer('guarded', [
                'bind_ip'         => false,
                'bind_ua'         => false,
                'allowed_origins' => ['https://example.com'],
            ]);

        $token = $csrf->generateFor('guarded');
        $this->assertTrue($csrf->validateFor('guarded', $token, null, null, 'https://example.com'));
    }

    /**
     * Token is rejected when the passed origin does not match the container whitelist.
     */
    public function testOriginScopeBlocksNonMatchingOrigin(): void
    {
        $csrf = (new Csrf(str_repeat('G', 32), 900))
            ->withContainer('guarded', [
                'bind_ip'         => false,
                'bind_ua'         => false,
                'allowed_origins' => ['https://example.com'],
            ]);

        $token = $csrf->generateFor('guarded');
        $this->assertFalse($csrf->validateFor('guarded', $token, null, null, 'https://attacker.example.org'));
    }

    /**
     * Empty allowed_origins list imposes no restriction — null origin passes.
     */
    public function testOriginScopeEmptyListPermitsAll(): void
    {
        $csrf = (new Csrf(str_repeat('H', 32), 900))
            ->withContainer('open', [
                'bind_ip'         => false,
                'bind_ua'         => false,
                'allowed_origins' => [],
            ]);

        $token = $csrf->generateFor('open');
        $this->assertTrue($csrf->validateFor('open', $token, null, null, null));
    }

    /**
     * Strict origin mode rejects validation when no origin can be resolved.
     */
    public function testOriginScopeStrictBlocksNullOrigin(): void
    {
        unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_REFERER']);

        $csrf = (new Csrf(str_repeat('I', 32), 900))
            ->withContainer('strict', [
                'bind_ip'         => false,
                'bind_ua'         => false,
                'allowed_origins' => ['https://example.com'],
                'origin_mode'     => 'strict',
            ]);

        $token = $csrf->generateFor('strict');
        $this->assertFalse($csrf->validateFor('strict', $token, null, null, null));
    }

    /**
     * Lenient origin mode (default) passes validation when no origin can be resolved.
     */
    public function testOriginScopeLenientAllowsNullOrigin(): void
    {
        unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_REFERER']);

        $csrf = (new Csrf(str_repeat('J', 32), 900))
            ->withContainer('lenient', [
                'bind_ip'         => false,
                'bind_ua'         => false,
                'allowed_origins' => ['https://example.com'],
                'origin_mode'     => 'lenient',
            ]);

        $token = $csrf->generateFor('lenient');
        $this->assertTrue($csrf->validateFor('lenient', $token, null, null, null));
    }

    /**
     * Origin is resolved automatically from $_SERVER when no explicit override is passed.
     */
    public function testOriginScopeAutoResolvedFromServer(): void
    {
        $_SERVER['HTTP_ORIGIN'] = 'https://example.com';

        $csrf = (new Csrf(str_repeat('K', 32), 900))
            ->withContainer('auto', [
                'bind_ip'         => false,
                'bind_ua'         => false,
                'allowed_origins' => ['https://example.com'],
            ]);

        $token = $csrf->generateFor('auto');
        $this->assertTrue($csrf->validateFor('auto', $token));

        unset($_SERVER['HTTP_ORIGIN']);
    }

    /**
     * Wildcard pattern in allowed_origins matches a single subdomain.
     */
    public function testOriginScopeWildcardSubdomain(): void
    {
        $csrf = (new Csrf(str_repeat('L', 32), 900))
            ->withContainer('wildcard', [
                'bind_ip'         => false,
                'bind_ua'         => false,
                'allowed_origins' => ['*.example.com'],
            ]);

        $token = $csrf->generateFor('wildcard');
        $this->assertTrue($csrf->validateFor('wildcard', $token, null, null, 'https://api.example.com'));

        $token = $csrf->regenerateFor('wildcard');
        $this->assertFalse($csrf->validateFor('wildcard', $token, null, null, 'https://a.b.example.com'));
    }

    /* ===================== Csrf origin-binding integration tests ===================== */

    /**
     * Matching normalized origin validates successfully.
     */
    public function testOriginBindingMatchingOriginIsValid(): void
    {
        $csrf = (new Csrf(str_repeat('M', 32), 900))
            ->withContainer('bound', [
                'bind_ip'     => false,
                'bind_ua'     => false,
                'origin'      => 'https://example.com',
            ]);

        $token = $csrf->generateFor('bound');
        $this->assertTrue($csrf->validateFor('bound', $token, null, null, 'https://example.com'));
    }

    /**
     * A different scheme is rejected.
     */
    public function testOriginBindingDifferentSchemeIsRejected(): void
    {
        $csrf = (new Csrf(str_repeat('N', 32), 900))
            ->withContainer('bound', [
                'bind_ip'     => false,
                'bind_ua'     => false,
                'origin'      => 'https://example.com',
            ]);

        $token = $csrf->generateFor('bound');
        $this->assertFalse($csrf->validateFor('bound', $token, null, null, 'http://example.com'));
    }

    /**
     * A different host is rejected.
     */
    public function testOriginBindingDifferentHostIsRejected(): void
    {
        $csrf = (new Csrf(str_repeat('O', 32), 900))
            ->withContainer('bound', [
                'bind_ip'     => false,
                'bind_ua'     => false,
                'origin'      => 'https://example.com',
            ]);

        $token = $csrf->generateFor('bound');
        $this->assertFalse($csrf->validateFor('bound', $token, null, null, 'https://evil.example.org'));
    }

    /**
     * A subdomain is treated as a distinct origin and rejected.
     */
    public function testOriginBindingSubdomainIsRejected(): void
    {
        $csrf = (new Csrf(str_repeat('P', 32), 900))
            ->withContainer('bound', [
                'bind_ip'     => false,
                'bind_ua'     => false,
                'origin'      => 'https://example.com',
            ]);

        $token = $csrf->generateFor('bound');
        $this->assertFalse($csrf->validateFor('bound', $token, null, null, 'https://sub.example.com'));
    }

    /**
     * Explicit default HTTPS port normalizes to the same origin and validates.
     */
    public function testOriginBindingDefaultHttpsPortNormalizes(): void
    {
        $csrf = (new Csrf(str_repeat('Q', 32), 900))
            ->withContainer('bound', [
                'bind_ip'     => false,
                'bind_ua'     => false,
                'origin'      => 'https://example.com',
            ]);

        $token = $csrf->generateFor('bound');
        $this->assertTrue($csrf->validateFor('bound', $token, null, null, 'https://example.com:443'));
    }

    /**
     * A non-default port is a distinct origin and is rejected.
     */
    public function testOriginBindingDifferentPortIsRejected(): void
    {
        $csrf = (new Csrf(str_repeat('R', 32), 900))
            ->withContainer('bound', [
                'bind_ip'     => false,
                'bind_ua'     => false,
                'origin'      => 'https://example.com',
            ]);

        $token = $csrf->generateFor('bound');
        $this->assertFalse($csrf->validateFor('bound', $token, null, null, 'https://example.com:8443'));
    }

    /**
     * Hostname casing is normalized before comparison.
     */
    public function testOriginBindingUppercaseHostnameNormalizes(): void
    {
        $csrf = (new Csrf(str_repeat('S', 32), 900))
            ->withContainer('bound', [
                'bind_ip'     => false,
                'bind_ua'     => false,
                'origin'      => 'https://example.com',
            ]);

        $token = $csrf->generateFor('bound');
        $this->assertTrue($csrf->validateFor('bound', $token, null, null, 'https://EXAMPLE.COM'));
    }

    /**
     * A missing request origin is rejected when origin binding is configured (fail-closed).
     */
    public function testOriginBindingMissingRequestOriginIsRejected(): void
    {
        unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_REFERER']);

        $csrf = (new Csrf(str_repeat('T', 32), 900))
            ->withContainer('bound', [
                'bind_ip'     => false,
                'bind_ua'     => false,
                'origin'      => 'https://example.com',
            ]);

        $token = $csrf->generateFor('bound');
        $this->assertFalse($csrf->validateFor('bound', $token, null, null, null));
    }

    /**
     * Leaving 'origin' unset (default null) means the request origin never affects validation.
     */
    public function testOriginBindingDisabledDoesNotAffectValidation(): void
    {
        $csrf = (new Csrf(str_repeat('U', 32), 900))
            ->withContainer('unbound', [
                'bind_ip' => false,
                'bind_ua' => false,
            ]);

        $token = $csrf->generateFor('unbound');
        $this->assertTrue($csrf->validateFor('unbound', $token, null, null, 'https://anything.example.net'));
        $token = $csrf->regenerateFor('unbound');
        $this->assertTrue($csrf->validateFor('unbound', $token, null, null, null));
    }

    /**
     * Tampering with the encrypted token invalidates the AES-GCM auth tag before
     * origin comparison is ever reached.
     */
    public function testOriginBindingTamperedTokenFailsAuthentication(): void
    {
        $csrf = (new Csrf(str_repeat('V', 32), 900))
            ->withContainer('bound', [
                'bind_ip'     => false,
                'bind_ua'     => false,
                'origin'      => 'https://example.com',
            ]);

        $token = $csrf->generateFor('bound');

        $raw = base64_decode($token, true);
        $this->assertIsString($raw);
        $tampered = substr($raw, 0, -1) . chr(ord(substr($raw, -1)) ^ 0x01);
        $tamperedToken = base64_encode($tampered);

        $this->assertFalse($csrf->validateFor('bound', $tamperedToken, null, null, 'https://example.com'));
    }

    /**
     * A configured 'origin' that fails to normalize (malformed/unsupported scheme)
     * fails loudly at generation time instead of silently embedding an empty value.
     */
    public function testOriginBindingWithMalformedOriginThrows(): void
    {
        $csrf = (new Csrf(str_repeat('W', 32), 900))
            ->withContainer('misconfigured', [
                'bind_ip' => false,
                'bind_ua' => false,
                'origin'  => 'not-a-valid-origin',
            ]);

        $this->expectException(\RuntimeException::class);
        $csrf->generateFor('misconfigured');
    }
}
