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

## Garbage Collection (File Cache)

```bash
php bin/garbage_collector.php
```

## License

MIT
