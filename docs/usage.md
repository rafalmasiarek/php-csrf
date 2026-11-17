## Features

- Stateless encrypted token (payload: token, ip, ua, origin, iat, container id)
- AES‑256‑GCM with IV + auth tag, AAD binds to container id/prefix
- Per‑container isolation: replay across forms is impossible
- Configurable bindings (IP/UA/origin) per container, plus a separate `allowed_origins` whitelist
- Optional session-bound HMAC proof (`_csrf_proof`), key-separated from the AES-GCM key (HKDF)
- Optional per-container `private_key`: fully decouple one container's keys from every other
  container and from the instance's master key — for a separately deployed consumer that must
  issue/validate just that container's tokens without ever learning the master key
- Tokens are always single-use (consumed on successful validation, not configurable)
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


## Examples

See [`example/`](example/) for drop‑in snippets:
- `basic/index.php`
- `containers/index.php`
- `fileCache/index.php`
- `ipOverride/index.php`
- `mysql/schema.sql`

## View Helpers

All three helpers below render through `HtmlHelper::input()`, which transparently emits a
`_csrf_proof` hidden field alongside `_csrf` whenever a session is active — no changes needed
to benefit from it (see [Session-Bound Proof](#session-bound-proof-_csrf_proof)).

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
