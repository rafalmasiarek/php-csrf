<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use rafalmasiarek\Csrf\Csrf;
use rafalmasiarek\Csrf\Helpers\HtmlHelper;

final class HtmlHelperTest extends TestCase
{
    /**
     * The default container emits only the _csrf field (plus _csrf_proof,
     * since a session is active in the test bootstrap) and no _csrf_container.
     */
    public function testInputForDefaultContainerOmitsContainerField(): void
    {
        $csrf = new Csrf(str_repeat('A', 32), 900);
        $html = HtmlHelper::input($csrf);

        $this->assertStringContainsString('name="_csrf"', $html);
        $this->assertStringNotContainsString('_csrf_container', $html);
    }

    /**
     * A named container emits both _csrf and _csrf_container.
     */
    public function testInputForNamedContainerEmitsContainerField(): void
    {
        $csrf = (new Csrf(str_repeat('B', 32), 900))->withContainer('profile', []);
        $html = HtmlHelper::input($csrf, 'profile');

        $this->assertStringContainsString('name="_csrf"', $html);
        $this->assertStringContainsString('name="_csrf_container" value="profile"', $html);
    }

    /**
     * A session-bound proof is available in the test bootstrap, so input()
     * transparently emits a matching _csrf_proof field.
     */
    public function testInputEmitsProofFieldWhenSessionActive(): void
    {
        $csrf = new Csrf(str_repeat('C', 32), 900);
        $html = HtmlHelper::input($csrf);

        $this->assertStringContainsString('name="_csrf_proof"', $html);
    }

    /**
     * The emitted token, and matching proof, validate together end-to-end.
     */
    public function testEmittedFieldsValidateTogether(): void
    {
        $csrf = (new Csrf(str_repeat('D', 32), 900))->withContainer('profile', []);
        $html = HtmlHelper::input($csrf, 'profile');

        preg_match('/name="_csrf" value="([^"]+)"/', $html, $tokenMatch);
        preg_match('/name="_csrf_proof" value="([^"]+)"/', $html, $proofMatch);

        $this->assertNotEmpty($tokenMatch[1] ?? null);
        $this->assertNotEmpty($proofMatch[1] ?? null);

        $token = htmlspecialchars_decode($tokenMatch[1], ENT_QUOTES);
        $proof = htmlspecialchars_decode($proofMatch[1], ENT_QUOTES);

        $this->assertTrue($csrf->validateFor('profile', $token, null, null, null, $proof));
    }

    /**
     * token() returns the raw encrypted value without HTML wrapping or a proof.
     */
    public function testTokenReturnsRawValue(): void
    {
        $csrf = new Csrf(str_repeat('E', 32), 900);
        $token = HtmlHelper::token($csrf);

        $this->assertIsString($token);
        $this->assertStringNotContainsString('<input', $token);
        $this->assertTrue($csrf->validateFor('default', $token));
    }
}
