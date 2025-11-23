<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * Provides client context (IP, User-Agent) for CSRF binding.
 * Default implementation reads from $_SERVER, but you can inject your own.
 */
interface ClientContextProviderInterface
{
    public function getIp(): string;

    public function getUserAgent(): string;
}
