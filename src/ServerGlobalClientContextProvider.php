<?php

declare(strict_types=1);

namespace rafalmasiarek\Csrf;

/**
 * Default client context provider that reads from $_SERVER.
 */
final class ServerGlobalClientContextProvider implements ClientContextProviderInterface
{
    public function getIp(): string
    {
        return isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])
            ? $_SERVER['REMOTE_ADDR']
            : '';
    }

    public function getUserAgent(): string
    {
        return isset($_SERVER['HTTP_USER_AGENT']) && is_string($_SERVER['HTTP_USER_AGENT'])
            ? $_SERVER['HTTP_USER_AGENT']
            : '';
    }
}
