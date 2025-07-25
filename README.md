# Encrypted CSRF Token Library

A secure, stateless CSRF protection system using encrypted fingerprints containing:
- CSRF token
- Client IP
- User-Agent
- Timestamp (`iat`)

Encrypted with AES-256-GCM and compatible with caching layers.

## Features

- Stateless CSRF token with embedded fingerprint
- AES-256-GCM encryption with IV and tag
- `iat` timestamp support (TTL)
- Optional caching (file, MySQL, Redis)
- Read-only cache support
- Garbage collector for file cache

## Usage

See `examples/` for usage examples.

## Upgrade Notice (from v1.0.0)

In versions prior to `1.1.0`, the default namespace was:

```php
use CsrfToken\Security\EncryptedCsrfToken;
```

Starting from version `1.1.0` and above, the namespace has changed to:

```php
use rafalmasiarek\CsrfToken\EncryptedCsrfToken;
```

**Action required:**  
If you're upgrading from version `1.0.0`, update all references to `EncryptedCsrfToken` in your codebase to use the new namespace.

This change was made to follow proper PSR-4 naming conventions and prevent naming conflicts in larger applications or when used as a dependency.

## Garbage Collection (File Cache)

```bash
php bin/garbage_collector.php
```

## License

MIT
