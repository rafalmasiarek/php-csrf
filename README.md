# PHP CSRF — Encrypted, Container‑Aware Tokens

A secure CSRF protection library with **AES‑256‑GCM** encryption and **per‑form containers**.
Each form (container) has its own session bucket, derived key (HKDF) and optional pepper.
Tokens are bound to container id, client IP and User‑Agent (both configurable).

## Features

- Stateless encrypted token (payload: token, ip, ua, iat, container id)
- AES‑256‑GCM with IV + auth tag, AAD binds to container id/prefix
- Per‑container isolation: replay across forms is impossible
- Configurable bindings (IP/UA) per container
- TTL support (set `0` to disable expiry — not recommended)
- Optional cache layer (File / MySQL / Redis) for fast‑path validation
- Backwards compatible API: `generate()`/`validate()` still work for the `"default"` container

## Install

```bash
composer require rafalmasiarek/php-csrf
```

## Quick Start

```php
use rafalmasiarek\Csrf\Csrf;

session_start();

$csrf = new Csrf($masterKey32Bytes, 900); // TTL=900s
$token = $csrf->generate();               // default container
// <input type="hidden" name="_csrf" value="$token">
```

Validation:

```php
if (!$csrf->validate($_POST['_csrf'] ?? null)) {
    http_response_code(419);
    exit('CSRF verification failed');
}
```

## Containers (Multiple Forms)

```php
use rafalmasiarek\Csrf\{Csrf, CsrfCacheWrapper, FileStorage};

$csrf = (new Csrf($masterKey32Bytes, 900))
    ->withContainer('signup', ['prefix' => 'auth_', 'bind_ip' => true,  'bind_ua' => true])
    ->withContainer('profile', ['prefix' => 'user_', 'bind_ip' => false, 'bind_ua' => true]);

$cache = new FileStorage(__DIR__ . '/var/csrf-cache'); // or MysqlStorage / RedisStorage
$csrfCached = new CsrfCacheWrapper($csrf, $cache);

// View:
$tokenSignup = $csrfCached->generateFor('signup');
$tokenProfile = $csrfCached->generateFor('profile');

// POST handler:
$ok = $csrfCached->validateFor('signup', $_POST['_csrf'] ?? '');
```

## Storage Options

- `FileStorage($dir)` — writes JSON files (hashed filenames)
- `MysqlStorage(PDO $pdo)` — uses table `csrf_cache(token_hash, payload JSON, created_at)`
- `RedisStorage(Redis $redis, string $prefix = 'csrf:', int $ttl = 900)`

> Storage keys are hashed; for multi‑containers we pass a composite `"<container>|<token>"` to avoid collisions.

## Security Notes

- Keep the **master key** (32 bytes) secret. Rotate periodically.
- Prefer enabling **IP/UA binding**. Disable only if your environment makes them unstable.
- Set a **reasonable TTL**. `0` (no expiry) is supported but not recommended.
- Tokens are **burned after successful validation** (per container).

## Migration

### From 1.2.x → 132.0

- **What changed**: The library is now **container‑aware**. Internal session storage moved under `$_SESSION['_csrf_v2'][<prefix><container>]` and tokens are bound to container id via AAD and payload.
- **Backwards compatibility**: Existing calls to `generate()` / `validate()` continue to work for the implicit `"default"` container.
- **Recommended**: Start calling `generateFor('<form-id>')` / `validateFor('<form-id>', $token)` for each separate form.

### From 1.0.0 → 1.1.x

- Namespace unified under `rafalmasiarek\Csrf` and PSR‑4 autoloading.

## Examples

See [`example/`](example/) for drop‑in snippets:
- `basic/index.php`
- `containers/index.php`
- `mysql/schema.sql`

## License

MIT


## View Helpers

### Plates (League\Plates)
```php
use League\Plates\Engine;
use rafalmasiarek\Csrf\Csrf;
use rafalmasiarek\Csrf\Helpers\Plates\CsrfExtension;

$view = new Engine(__DIR__.'/views');
$csrf = new Csrf($masterKey, 900);
CsrfExtension::register($view, $csrf);

// In template: <?= csrf_field('signup') ?>
```

### Twig
```php
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use rafalmasiarek\Csrf\Csrf;
use rafalmasiarek\Csrf\Helpers\Twig\CsrfExtension;

$twig = new Environment(new FilesystemLoader(__DIR__.'/views'));
$csrf = new Csrf($masterKey, 900);
$twig->addExtension(new CsrfExtension($csrf));

// In template: {{ csrf_field('signup')|raw }}
```

### Blade (Laravel)
```php
use Illuminate\View\Compilers\BladeCompiler;
use rafalmasiarek\Csrf\Csrf;
use rafalmasiarek\Csrf\Helpers\Blade\CsrfBlade;

// In a service provider boot():
CsrfBlade::register($this->app->make(BladeCompiler::class), app(Csrf::class));

// In Blade: @csrfField('signup')
```
