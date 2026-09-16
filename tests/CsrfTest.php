<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use rafalmasiarek\Csrf\Csrf;
use rafalmasiarek\Csrf\ClientContextProviderInterface;
use rafalmasiarek\Csrf\OriginMatcher;
use rafalmasiarek\Csrf\OriginProviderInterface;
use rafalmasiarek\Csrf\SessionBindingProviderInterface;

/**
 * Test double: mutable session binding, so a single Csrf instance can
 * simulate the session identifier changing between generation and validation.
 */
final class FixedSessionBindingProvider implements SessionBindingProviderInterface
{
    public function __construct(public string $value)
    {
    }

    public function getSessionBinding(): string
    {
        return $this->value;
    }
}

/**
 * Test double: IP/UA context provider that does NOT also implement
 * OriginProviderInterface, to verify origin resolution falls back correctly.
 */
final class IpUaOnlyContextProvider implements ClientContextProviderInterface
{
    public function getIp(): string
    {
        return '198.51.100.7';
    }

    public function getUserAgent(): string
    {
        return 'ip-ua-only/1.0';
    }
}

/**
 * Test double: fixed origin provider, independent of any context provider.
 */
final class FixedOriginProvider implements OriginProviderInterface
{
    public function __construct(private ?string $value)
    {
    }

    public function getOrigin(): ?string
    {
        return $this->value;
    }
}

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

    /* ===================== Csrf _csrf_proof integration tests ===================== */

    /**
     * A valid pair (token + proof) issued and validated within the same session validates.
     */
    public function testProofValidPairValidates(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('X', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');
        $this->assertNotNull($pair->proof);
        $this->assertTrue($csrf->validateFor('profile', $pair->token, null, null, null, $pair->proof));
    }

    /**
     * A correct token paired with a random/wrong proof is rejected.
     */
    public function testProofWrongProofIsRejected(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('Y', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');
        $this->assertFalse($csrf->validateFor('profile', $pair->token, null, null, null, 'not-the-real-proof'));
    }

    /**
     * A modified token invalidates AES-GCM authentication before the (now stale)
     * original proof is even relevant.
     */
    public function testProofModifiedTokenIsRejected(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('Z', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');

        $raw = base64_decode($pair->token, true);
        $this->assertIsString($raw);
        $tampered = substr($raw, 0, -1) . chr(ord(substr($raw, -1)) ^ 0x01);
        $tamperedToken = base64_encode($tampered);

        $this->assertFalse($csrf->validateFor('profile', $tamperedToken, null, null, null, $pair->proof));
    }

    /**
     * A pair issued under one session binding is rejected when validated under another.
     */
    public function testProofDifferentSessionIsRejected(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('a', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');

        $provider->value = 'session-B';
        $this->assertFalse($csrf->validateFor('profile', $pair->token, null, null, null, $pair->proof));
    }

    /**
     * Session regeneration (session binding changes after issuance) invalidates the old pair.
     */
    public function testProofSessionRegenerationInvalidatesOldPair(): void
    {
        $provider = new FixedSessionBindingProvider('session-before-login');
        $csrf = (new Csrf(str_repeat('b', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');

        $provider->value = 'session-after-login';
        $this->assertFalse($csrf->validateFor('profile', $pair->token, null, null, null, $pair->proof));
    }

    /**
     * A proof issued for one container is rejected when validated against another.
     */
    public function testProofDifferentContainerIsRejected(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('c', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false])
            ->withContainer('delete-account', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');
        $this->assertFalse($csrf->validateFor('delete-account', $pair->token, null, null, null, $pair->proof));
    }

    /**
     * require_proof=true rejects validation when no proof is submitted.
     */
    public function testProofMissingIsRejectedWhenRequired(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('d', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false, 'require_proof' => true]);

        $pair = $csrf->issueFor('profile');
        $this->assertFalse($csrf->validateFor('profile', $pair->token));
    }

    /**
     * Default (require_proof=false, "optional") behavior: a missing proof does not
     * block validation — the legacy token-only check still applies.
     */
    public function testProofMissingIsTransparentByDefault(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('e', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');
        $this->assertTrue($csrf->validateFor('profile', $pair->token));
    }

    /**
     * Even with require_proof=false, a submitted-but-wrong proof is still rejected —
     * the proof is transparent (checked whenever present), never silently ignored.
     */
    public function testProofSubmittedWrongIsRejectedEvenWhenNotRequired(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('f', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');
        $this->assertFalse($csrf->validateFor('profile', $pair->token, null, null, null, 'garbage-proof-value'));
    }

    /**
     * A malformed (non-base64url) proof value is rejected like any other mismatch.
     */
    public function testProofMalformedValueIsRejected(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('g', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false, 'require_proof' => true]);

        $pair = $csrf->issueFor('profile');
        $this->assertFalse($csrf->validateFor('profile', $pair->token, null, null, null, '!!!not-base64url!!!'));
    }

    /**
     * An oversized proof is rejected without attempting HMAC computation.
     */
    public function testProofOversizedValueIsRejected(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('h', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');
        $oversized = str_repeat('a', 1000);
        $this->assertFalse($csrf->validateFor('profile', $pair->token, null, null, null, $oversized));
    }

    /**
     * Proof key derivation (HKDF domain separation) does not affect AES-GCM token
     * decryption — a token issued via issueFor() still validates via plain
     * validateFor() with no proof supplied at all.
     */
    public function testProofKeySeparationDoesNotAffectTokenDecryption(): void
    {
        $provider = new FixedSessionBindingProvider('session-A');
        $csrf = (new Csrf(str_repeat('i', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');
        $this->assertTrue($csrf->validateFor('profile', $pair->token));
    }

    /**
     * A custom SessionBindingProviderInterface is used instead of the native PHP session id.
     */
    public function testCustomSessionBindingProviderIsUsed(): void
    {
        $provider = new FixedSessionBindingProvider('custom-session-value');
        $csrf = (new Csrf(str_repeat('j', 32), 900, null, $provider))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');
        $this->assertNotNull($pair->proof);
        $this->assertTrue($csrf->validateFor('profile', $pair->token, null, null, null, $pair->proof));
    }

    /**
     * Without an explicit SessionBindingProviderInterface, the default
     * PhpSessionBindingProvider (native session_id()) is used and works out of the box.
     */
    public function testIssueForUsesDefaultPhpSessionBindingProvider(): void
    {
        $csrf = (new Csrf(str_repeat('k', 32), 900))
            ->withContainer('profile', ['bind_ip' => false, 'bind_ua' => false]);

        $pair = $csrf->issueFor('profile');
        $this->assertNotNull($pair->proof);
        $this->assertTrue($csrf->validateFor('profile', $pair->token, null, null, null, $pair->proof));
    }

    /* ===================== OriginProviderInterface resolution tests ===================== */

    /**
     * A custom ClientContextProviderInterface that does NOT also implement
     * OriginProviderInterface still gets automatic origin resolution, via the
     * fallback to ServerGlobalClientContextProvider — origin-scope checks are
     * not silently disabled just because a custom IP/UA provider was injected.
     */
    public function testOriginResolvedViaFallbackWhenContextProviderLacksOriginInterface(): void
    {
        $_SERVER['HTTP_ORIGIN'] = 'https://example.com';

        $csrf = (new Csrf(str_repeat('l', 32), 900, new IpUaOnlyContextProvider()))
            ->withContainer('guarded', [
                'bind_ip'         => false,
                'bind_ua'         => false,
                'allowed_origins' => ['https://example.com'],
            ]);

        $token = $csrf->generateFor('guarded');
        $this->assertTrue($csrf->validateFor('guarded', $token));

        unset($_SERVER['HTTP_ORIGIN']);
    }

    /**
     * An explicit $originProvider constructor argument takes precedence over
     * both an override-less resolution and the context provider's own origin.
     */
    public function testExplicitOriginProviderIsUsed(): void
    {
        $_SERVER['HTTP_ORIGIN'] = 'https://from-server-global.example.com';

        $csrf = (new Csrf(
            str_repeat('m', 32),
            900,
            null,
            null,
            new FixedOriginProvider('https://from-custom-provider.example.com')
        ))->withContainer('guarded', [
            'bind_ip'         => false,
            'bind_ua'         => false,
            'allowed_origins' => ['https://from-custom-provider.example.com'],
        ]);

        $token = $csrf->generateFor('guarded');
        $this->assertTrue($csrf->validateFor('guarded', $token));

        unset($_SERVER['HTTP_ORIGIN']);
    }
}
