<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * An atomically issued CSRF token and its matching session-bound proof.
 *
 * The token and proof are always refreshed together — never mix a token
 * from one pair with a proof from another.
 *
 * @package rafalmasiarek\Csrf
 */
final readonly class CsrfPair
{
    /**
     * @param string      $token The encrypted _csrf token value.
     * @param string|null $proof The _csrf_proof value, or null when the
     *                           session binding could not be resolved.
     */
    public function __construct(
        public string $token,
        public ?string $proof,
    ) {
    }
}
