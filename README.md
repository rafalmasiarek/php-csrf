# php-csrf
A secure CSRF protection library with **AES‑256‑GCM** encryption and **per‑form containers**.
Each form (container) has its own session bucket, derived key (HKDF) and optional pepper.
Tokens are bound to container id, client IP, User‑Agent, and origin (all configurable), with
an optional session-bound HMAC proof as a second, independent field.

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

## Security Notes

- Keep the **master key** (32 bytes) secret. Rotate periodically.
- Prefer enabling **IP/UA binding**. Disable only if your environment makes them unstable.
- Set a **reasonable TTL**. `0` (no expiry) is supported but not recommended.
- Tokens are **burned after successful validation** (per container).

---

## Client Context Provider (IP / User-Agent injection)

Since version **1.3.2** the library supports **external injection of client IP and User-Agent**, instead of relying solely on `$_SERVER`.

### Passing IP/UA explicitly

```php
$token = $csrf->generate($realIp, $realUa);
$isValid = $csrf->validate($submittedToken, $realIp, $realUa);
```

Container-specific:

```php
$token = $csrf->generateFor('signup', $realIp, $realUa);
$ok = $csrf->validateFor('signup', $submittedToken, $realIp, $realUa);
```

### ClientContextProviderInterface

```php
use rafalmasiarek\Csrf\ClientContextProviderInterface;

class SlimRequestProvider implements ClientContextProviderInterface {
    public function __construct(private \Psr\Http\Message\ServerRequestInterface $request) {}

    public function getIp(): string {
        return $this->request->getAttribute('client_ip') ?? '';
    }

    public function getUserAgent(): string {
        return $this->request->getHeaderLine('User-Agent');
    }
}
```

Usage:

```php
$csrf = new Csrf($key, 900, new SlimRequestProvider($request));
```

---

## Origin Binding

Independent from IP/UA binding: when a container has a trusted `origin` configured, that
origin is embedded in the encrypted payload at generation time and enforced against the
resolved request `Origin` at validation time. Unlike `allowed_origins` (below), this binds
one specific token instance to one specific origin, not a request to a whitelist.

```php
$csrf = (new Csrf($masterKey32Bytes, 900))
    ->withContainer('transfer-funds', [
        'bind_ip' => false,
        'bind_ua' => true,
        'origin'  => 'https://app.example.com', // trusted, static — never from a request header
    ]);

$token = $csrf->generateFor('transfer-funds');
// throws \RuntimeException at generation time if 'origin' is set but does not
// normalize to a valid http(s) origin (fail loud on misconfiguration)

$ok = $csrf->validateFor(
    'transfer-funds',
    $_POST['_csrf'] ?? null,
    null,
    null,
    $_SERVER['HTTP_ORIGIN'] ?? null // or omit — resolved automatically via OriginProviderInterface
);
```

Rules:

- Origins are normalized before comparison: lowercase scheme/host, no trailing slash, default
  ports (`443` for `https`, `80` for `http`) omitted. `https://APP.example.com:443/` and
  `https://app.example.com` are equal; `https://app.example.com:8443` is not.
  Subdomains are distinct origins (`https://api.example.com` ≠ `https://example.com`).
- A missing request origin is always rejected when binding is active (fail-closed) — there is
  no lenient mode for this check.
- Comparison is constant-time (`hash_equals`).
- Leaving `origin` unset (default `null`) disables the check entirely; it never affects
  containers that don't configure it.

### Origin Scope (`allowed_origins`)

A separate, coarser mechanism: a per-container whitelist checked independently of any single
token, useful when multiple trusted origins must be accepted (e.g. web + mobile webview).

```php
$csrf = (new Csrf($masterKey32Bytes, 900))
    ->withContainer('checkout', [
        'allowed_origins' => ['https://app.example.com', '*.example.com'],
        'origin_mode'     => 'strict', // 'strict': missing origin = reject; 'lenient' (default): missing origin = accept
    ]);
```

Supports exact origins, scheme-free hosts (`example.com` matches any scheme), and single-label
wildcards (`*.example.com` matches `https://api.example.com`, not `https://a.b.example.com`).
Run both mechanisms together when you want a specific token bound to a specific origin *and* a
broader fallback whitelist for multi-origin deployments.

---

## Dedicated Per-Container Key (`private_key`)

Every container normally derives its encryption and proof keys (HKDF) from the one master
`$cipherKey` passed to the `Csrf` constructor — isolated from other containers, but all still
ultimately decryptable by anyone holding that one master key. Setting `private_key` on a
container replaces the master key as that container's HKDF base entirely:

```php
// The app issuing tokens — still has its own master key for every other container.
$csrf = (new Csrf($masterKey32Bytes, 900))
    ->withContainer('side-app', ['private_key' => $sideAppKey32Bytes]);

// A separately deployed consumer — only ever holds $sideAppKey32Bytes, never $masterKey32Bytes.
$sideCsrf = (new Csrf($anyUnrelated32ByteKey, 900))
    ->withContainer('side-app', ['private_key' => $sideAppKey32Bytes]);

$token = $csrf->generateFor('side-app');
$sideCsrf->validateFor('side-app', $token); // true — the two instances share only this one key
```

- Must be exactly 32 bytes; `withContainer()` throws `\InvalidArgumentException` otherwise.
- Applies to both the encryption key and the `_csrf_proof` key (same HKDF domain separation as
  the master-key case) — `require_proof` works the same way across independently-keyed instances.
- Leaving it unset (default `null`) is a no-op: the container derives from the master key, as
  before this option existed.
- The constructor's own master `$cipherKey` argument is unused for a container configured this
  way (any valid 32-byte placeholder works) — it still has to be supplied, since it's a
  constructor-level, not container-level, argument.

## Session-Bound Proof (`_csrf_proof`)

An optional second field, `_csrf_proof`, provides independent evidence that the submitted
`_csrf` token belongs to the current authenticated session — not just that it decrypts
correctly. It is an HMAC-SHA256 over the exact token, the container id, and a session-bound
value, keyed by a proof key derived independently from the AES-GCM encryption key (HKDF
domain separation: `csrf:<container>` vs. `csrf-proof:<container>`). This borrows the
session-binding principle from OWASP's Signed Double-Submit Cookie guidance; it is not a
literal double-submit-cookie implementation — no cookie is involved, the library remains a
synchronizer-token design.

```php
$csrf = (new Csrf($masterKey32Bytes, 900))
    ->withContainer('transfer-funds', ['require_proof' => true]);

// Issue token + proof atomically — never mix a token from one pair with a proof from another:
$pair = $csrf->issueFor('transfer-funds');
// <input type="hidden" name="_csrf" value="<?= $pair->token ?>">
// <input type="hidden" name="_csrf_proof" value="<?= $pair->proof ?>">

// Validate — proof is transparent by default:
$ok = $csrf->validateFor(
    'transfer-funds',
    $_POST['_csrf'] ?? null,
    null, null, null,
    $_POST['_csrf_proof'] ?? null
);
```

Behavior:

- **Transparent**: a submitted proof is always verified (mismatch → reject); a missing proof
  is only rejected when the container sets `'require_proof' => true` (default `false`).
- `issueFor()` always computes a proof when a session is active; `generateFor()` never does
  (no behavior change for existing callers).
- The proof is bound to the *exact* encrypted token string. Regenerating the token via
  `generateFor()`/`issueFor()` invalidates any previously issued proof, and vice versa —
  always refresh both together.
- The session binding comes from `SessionBindingProviderInterface::getSessionBinding()`
  (default: native `session_id()`). Provide a custom implementation for framework-managed or
  JWT-backed sessions:

```php
use rafalmasiarek\Csrf\SessionBindingProviderInterface;

final class JwtSessionBindingProvider implements SessionBindingProviderInterface
{
    public function __construct(private string $jwtSessionClaim) {}

    public function getSessionBinding(): string
    {
        return $this->jwtSessionClaim; // must change on login/logout/privilege elevation
    }
}

$csrf = new Csrf($masterKey32Bytes, 900, null, new JwtSessionBindingProvider($claim));
```

Never bind to a static account attribute (user id, email) — the value must change whenever
the login session is regenerated, or a stolen token/proof pair from a previous session stays
valid across logins.

### Validation Order

```
missing _csrf                 -> reject
_csrf_proof (if submitted, or required) -> reject on mismatch/missing-when-required
allowed_origins whitelist     -> reject
AES-GCM decrypt/authenticate  -> reject on tamper
container id match            -> reject
server-side session state     -> reject if absent
IP / User-Agent binding       -> reject on mismatch
origin binding                -> reject on mismatch
expiry                        -> reject if expired
                              -> consume token (single-use), accept
```

---

## Token Lifecycle: Single-Use, Back Button, and Refreshing

Tokens are **always single-use**: `validateFor()` burns the server-side session state on
success. This is a hard-coded property of the library, not a configuration flag — plan the
UX around it rather than looking for a way to disable it.

### The Back button / BFCache problem

```
GET /checkout            -> server issues token T1
POST /checkout            -> T1 validated, consumed
user presses Back          -> browser may restore the /checkout page from BFCache
                              (the form still shows the now-consumed T1)
user re-submits             -> validateFor() returns false: T1 no longer exists server-side
```

This is the *correct*, intended outcome from a security standpoint — a consumed token must
never validate again. It is a UX problem to solve at the application layer, not a defect to
patch in the library.

### Refresh pattern

Expose a same-origin, `no-store` endpoint that issues a fresh pair on demand, and re-fetch it
whenever a page may be showing stale form state:

```php
// GET /csrf/refresh?container=checkout
$pair = $csrf->issueFor($_GET['container'] ?? 'default');

header('Content-Type: application/json');
header('Cache-Control: no-store, private');
echo json_encode(['csrf' => $pair->token, 'csrf_proof' => $pair->proof]);
```

```js
window.addEventListener('pageshow', (event) => {
    if (!event.persisted) return; // only act on a BFCache restore

    document.querySelectorAll('[data-csrf-container]').forEach(async (form) => {
        const container = form.dataset.csrfContainer;
        const res = await fetch(`/csrf/refresh?container=${encodeURIComponent(container)}`, {
            credentials: 'same-origin',
            cache: 'no-store',
        });
        const { csrf, csrf_proof } = await res.json();

        form.querySelector('[name="_csrf"]').value = csrf;
        const proofField = form.querySelector('[name="_csrf_proof"]');
        if (proofField && csrf_proof) proofField.value = csrf_proof;
    });
});
```

Do not put the token or proof in a URL query string (history, logs, `Referer` leakage). The
refresh endpoint must only issue tokens on `GET` — never perform a state change there.

### Monitoring expiration

`getExpiresInFor()` reports remaining TTL without consuming the token, so a long-lived form
(e.g. a multi-step wizard left idle in a tab) can warn the user or refresh proactively before
submission fails:

```php
$secondsLeft = $csrf->getExpiresInFor('checkout'); // null = no token yet, 0 = expired, PHP_INT_MAX = TTL disabled
```

```js
// Client-side countdown fed by a value the server embedded when rendering the page.
let secondsLeft = 900;
setInterval(() => {
    secondsLeft--;
    if (secondsLeft === 60) {
        // e.g. show a "your session is about to expire" banner, or call the refresh endpoint proactively
    }
}, 1000);
```

Applications that intentionally reuse a token across multiple requests are outside this
library's model — `single_use` is not configurable, by design.

---

## Migration

### Upgrading to this release (Origin Binding, Session-Bound Proof)

- **PHP requirement raised to `>=8.2`** (`CsrfPair` is a `readonly` class — the class-level
  `readonly` modifier is PHP 8.2+; readonly *properties* alone would only need 8.1). This is a
  breaking change for consumers on PHP 7.4–8.0 — bump your own `composer.json` accordingly.
- **`Csrf::__construct()`** gained an optional 4th parameter, `?SessionBindingProviderInterface`.
  Existing call sites are unaffected.
- **`withContainer()`** gained two optional keys: `origin` (see Origin Binding) and
  `require_proof` (see Session-Bound Proof). Both default to disabled — existing container
  configs behave identically until you opt in.
- **`validateFor()` / `validateCachedFor()`** gained trailing optional parameters
  (`$proof`, and `$rawToken`/`$proof` respectively). Existing positional call sites are
  unaffected; `CsrfCacheWrapper::validateFor()` gained an optional trailing `$proof` too.
- **New**: `Csrf::issueFor()` and `CsrfCacheWrapper::issueFor()` return a `CsrfPair`
  (token + proof). `generateFor()` is unchanged and never computes a proof.
- **`HtmlHelper::input()`** (and therefore the Plates/Twig/Blade helpers, which all delegate
  to it) now calls `issueFor()` internally and transparently emits a `_csrf_proof` hidden
  field whenever a session is active. No template changes are required; the extra field has
  no effect on validation unless the receiving container sets `require_proof`.
- **Fixed**: `HtmlHelper::token()` was referenced by the Plates helper (`csrf_token()`) but
  did not exist, making that function fatal at call time. It is now implemented.

### From 1.2.1 → 1.3.x

- **What changed**: The library is now **container‑aware**. Internal session storage moved under `$_SESSION['_csrf_v2'][<prefix><container>]` and tokens are bound to container id via AAD and payload.
- **Backwards compatibility**: Existing calls to `generate()` / `validate()` continue to work for the implicit `"default"` container.
- **Recommended**: Start calling `generateFor('<form-id>')` / `validateFor('<form-id>', $token)` for each separate form.

### From 1.0.0 → 1.1.x

- Namespace unified under `rafalmasiarek\Csrf` and PSR‑4 autoloading.

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



## License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

```text
The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files, to deal in the Software
without restriction.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

Source: https://opensource.org/licenses/MIT
```
See [LICENSE](LICENSE) for full details.
## Authors

- Rafał Masiarek | [website](https://masiarek.pl) | [email](mailto:rafal@masiarek.pl) | [github](https://github.com/rafalmasiarek)


## Index

### Classes

- [`ArrayStorage`](#arraystorage) — `rafalmasiarek\Csrf`
- [`Csrf`](#csrf) — `rafalmasiarek\Csrf`
- [`CsrfCacheWrapper`](#csrfcachewrapper) — `rafalmasiarek\Csrf`
- [`CsrfPair`](#csrfpair) — `rafalmasiarek\Csrf`
- [`FileStorage`](#filestorage) — `rafalmasiarek\Csrf`
- [`CsrfBlade`](#csrfblade) — `rafalmasiarek\Csrf\Helpers\Blade`
- [`HtmlHelper`](#htmlhelper) — `rafalmasiarek\Csrf\Helpers`
- [`CsrfExtension`](#csrfextension) — `rafalmasiarek\Csrf\Helpers\Plates`
- [`CsrfExtension`](#csrfextension-1) — `rafalmasiarek\Csrf\Helpers\Twig`
- [`MysqlStorage`](#mysqlstorage) — `rafalmasiarek\Csrf`
- [`OriginMatcher`](#originmatcher) — `rafalmasiarek\Csrf`
- [`PhpSessionBindingProvider`](#phpsessionbindingprovider) — `rafalmasiarek\Csrf`
- [`RedisStorage`](#redisstorage) — `rafalmasiarek\Csrf`
- [`ServerGlobalClientContextProvider`](#serverglobalclientcontextprovider) — `rafalmasiarek\Csrf`

### Interfaces

- [`ClientContextProviderInterface`](#clientcontextproviderinterface) — `rafalmasiarek\Csrf`
- [`CsrfStorageInterface`](#csrfstorageinterface) — `rafalmasiarek\Csrf`
- [`OriginProviderInterface`](#originproviderinterface) — `rafalmasiarek\Csrf`
- [`SessionBindingProviderInterface`](#sessionbindingproviderinterface) — `rafalmasiarek\Csrf`

## `ArrayStorage`

*class* — `rafalmasiarek\Csrf\ArrayStorage` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ArrayStorage.php#L10)

In-memory array storage (useful for testing).

implements [`CsrfStorageInterface`](#csrfstorageinterface)

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$data` | `array<string, array>` | private | — |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`store()`](#arraystorage-store) | public | `void` | — |
| [`fetch()`](#arraystorage-fetch) | public | `?array` | — |
| [`remove()`](#arraystorage-remove) | public | `void` | — |

<details>
<summary><code>store()</code></summary>

#### `ArrayStorage store()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ArrayStorage.php#L15)

```php
public function store(string $encryptedToken, array $payload): void
```

| Param | Type | Description |
|---|---|---|
| `$encryptedToken` | `string` | — |
| `$payload` | `array` | — |

</details>

<details>
<summary><code>fetch()</code></summary>

#### `ArrayStorage fetch()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ArrayStorage.php#L20)

```php
public function fetch(string $encryptedToken): ?array
```

| Param | Type | Description |
|---|---|---|
| `$encryptedToken` | `string` | — |

**Returns:** `?array`

</details>

<details>
<summary><code>remove()</code></summary>

#### `ArrayStorage remove()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ArrayStorage.php#L26)

```php
public function remove(string $encryptedToken): void
```

| Param | Type | Description |
|---|---|---|
| `$encryptedToken` | `string` | — |

</details>

## `ClientContextProviderInterface`

*interface* — `rafalmasiarek\Csrf\ClientContextProviderInterface` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ClientContextProviderInterface.php#L11)

Provides client context (IP, User-Agent) for CSRF binding. Default implementation reads from $_SERVER, but you can inject your own.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`getIp()`](#clientcontextproviderinterface-getip) | public | `string` | — |
| [`getUserAgent()`](#clientcontextproviderinterface-getuseragent) | public | `string` | — |

<details>
<summary><code>getIp()</code></summary>

#### `ClientContextProviderInterface getIp()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ClientContextProviderInterface.php#L13)

```php
public function getIp(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>getUserAgent()</code></summary>

#### `ClientContextProviderInterface getUserAgent()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ClientContextProviderInterface.php#L15)

```php
public function getUserAgent(): string
```

**Returns:** `string`

</details>

## `Csrf`

*class* — `rafalmasiarek\Csrf\Csrf` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L40)

Container-aware CSRF with AES-256-GCM and per-container isolation. Backwards compatibility: - generate()/validate()/regenerate()/getExpiresIn()/clear() continue to work and operate on the "default" container. Security: - Each container has its own session bucket, derived key (HKDF), optional pepper, and AES-GCM Additional Authenticated Data (AAD) binding. - Token payload binds to container id (cid), IP (optional), UA (optional), origin (optional), and iat. - Optional per-container origin-scope: allowed_origins whitelist checked on validation. The origin is resolved automatically via the constructor's $originProvider (defaults to ServerGlobalClientContextProvider); pass an explicit $origin override to validateFor() otherwise. - Optional per-container origin binding: when container config 'origin' is set (non-null), that trusted origin is embedded in the payload at generation time and compared against the resolved request origin at validation time. This is independent from, and complementary to, the allowed_origins whitelist above. - Optional session-bound HMAC proof (_csrf_proof): issueFor() returns a CsrfPair (token + proof) where the proof is an HMAC-SHA256 over the exact opaque token, the container id, and a session-bound value (see SessionBindingProviderInterface), keyed by a key derived independently from the AES-GCM key (HKDF domain separation). The proof is transparent: passing it to validateFor()/validateCachedFor() always verifies it, while its absence is only rejected when the container config 'require_proof' is true. - Optional per-container 'private_key': when set, HKDF derives that container's encryption and proof keys from this key instead of the constructor's master $cipherKey — total key independence from every other container, including ones sharing the same Csrf instance/process. Meant for a separate, independently deployed consumer that must be able to issue/validate this one container's tokens without ever learning the master key.

**Depends on:** [`ClientContextProviderInterface`](#clientcontextproviderinterface), [`SessionBindingProviderInterface`](#sessionbindingproviderinterface), [`OriginProviderInterface`](#originproviderinterface)

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$sessionRoot` | `string` | private | Root session namespace for all CSRF state. |
| `$legacySessionKey` | `string` | private | Legacy single-key (kept for BC if someone clears manually). |
| `$cipherKey` | `string` | private | Master cipher key (32 bytes). |
| `$ttl` | `int` | private | Time-to-live (seconds). 0 means never expires. |
| `$lastPayload` | `?array` | private | Last generated or validated payload. |
| `$containerOptions` | `array<string, array{prefix: string, bind_ip: bool, bind_ua: bool, pepper: ?string, allowed_origins: list<string>, origin_mode: string, origin: ?string, require_proof: bool, private_key: ?string}>` | private | Per-container runtime options. Keys are container IDs, values are option arrays: - prefix (string) : prefix added to session bucket key - bind_ip (bool) : verify client IP (default: true) - bind_ua (bool) : verify User-Agent (default: true) - pepper (?string) : optional per-container binary secret for HKDF salt - allowed_origins (list<string>) : origin whitelist; empty = no restriction - origin_mode (string) : 'lenient' (null origin passes) \| 'strict' (null origin blocked) - origin (?string) : trusted origin; when non-null, it is embedded in the payload at generation and enforced against the request origin at validation (default: null = binding disabled) - require_proof (bool) : reject validation when _csrf_proof is missing (default: false) - private_key (?string) : 32-byte key; when set, this container's keys are derived from it instead of the master $cipherKey (default: null = derive from master, as before) |
| `$defaults` | `array<string, mixed>` | private | App-registered defaults, set once via setDefaults(). Applied to every container beneath CONTAINER_OPTION_DEFAULTS and above per-container options. |
| `$contextProvider` | [`ClientContextProviderInterface`](#clientcontextproviderinterface) | private | Provides client IP / User-Agent context. |
| `$sessionBindingProvider` | [`SessionBindingProviderInterface`](#sessionbindingproviderinterface) | private | Provides the session-bound value used for _csrf_proof. |
| `$originProvider` | [`OriginProviderInterface`](#originproviderinterface) | private | Provides the HTTP Origin for origin-scope validation and origin binding. |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#csrf-__construct) | public | — | — |
| [`withContainer()`](#csrf-withcontainer) | public | `$this` | Configure/override options for a container ID. Merges, in order: built-in defaults < setDefaults() < $options. |
| [`setDefaults()`](#csrf-setdefaults) | public | `$this` | Registers global default options applied to every container. Sits between the library's built-in fallback values and any per-container options passed to withContainer(): CONTAINER_OPTION_DEFAULTS < $defaults < withContainer(). Also applies to container ids used without prior withContainer() registration at all (e.g. ad-hoc container ids resolved at request time). |
| [`getContainerConfig()`](#csrf-getcontainerconfig) | public | `array{prefix: string, bind_ip: bool, bind_ua: bool, pepper: ?string, allowed_origins: list<string>, origin_mode: string, origin: ?string, require_proof: bool, private_key: ?string}` | Returns the fully-resolved effective configuration for a container id — built-in defaults, app-registered defaults (setDefaults()), and any per-container override (withContainer()), merged in that order. Works even when the container was never explicitly registered. |
| [`getTtl()`](#csrf-getttl) | public | `int` | — |
| [`generate()`](#csrf-generate) | public | `string` | Generate an encrypted token for the default container. |
| [`validate()`](#csrf-validate) | public | `bool` | Validate an encrypted token for the default container. |
| [`regenerate()`](#csrf-regenerate) | public | `string` | — |
| [`getExpiresIn()`](#csrf-getexpiresin) | public | `int\|null` | — |
| [`getLastPayload()`](#csrf-getlastpayload) | public | `array\|null` | — |
| [`clear()`](#csrf-clear) | public | `void` | Clear the default container token state. |
| [`generateFor()`](#csrf-generatefor) | public | `string` | Generate (or reuse unexpired) token for a container. |
| [`issueFor()`](#csrf-issuefor) | public | [`CsrfPair`](#csrfpair) | Generate a token together with its session-bound _csrf_proof, atomically. Unlike generateFor(), the proof is always computed here regardless of the container's 'require_proof' setting — that setting only controls whether validateFor()/validateCachedFor() reject a request missing the proof. Token and proof must always be refreshed together; never mix a token from one pair with a proof from another. |
| [`validateFor()`](#csrf-validatefor) | public | `bool` | Validate an encrypted token for a specific container. |
| [`validateCachedFor()`](#csrf-validatecachedfor) | public | `bool` | Validate a cached payload for a specific container (no decrypt). |
| [`regenerateFor()`](#csrf-regeneratefor) | public | `string` | Force new token for a container (clears previous state). |
| [`getExpiresInFor()`](#csrf-getexpiresinfor) | public | `int\|null` | Remaining lifetime for a container. |
| [`clearFor()`](#csrf-clearfor) | public | `void` | Clear token for a container. |
| [`resolveContainer()`](#csrf-resolvecontainer) | private | `array{bucketKey: string, cfg: array{prefix: string, bind_ip: bool, bind_ua: bool, pepper: ?string}}` | Resolve session bucket and merged options for a container. |
| [`isExpired()`](#csrf-isexpired) | public | `bool` | Check if a given session state is expired. |
| [`resolveIp()`](#csrf-resolveip) | private | `string` | Resolve IP address using explicit override or context provider. |
| [`resolveUserAgent()`](#csrf-resolveuseragent) | private | `string` | Resolve User-Agent using explicit override or context provider. |
| [`resolveOrigin()`](#csrf-resolveorigin) | private | `string\|null` | Resolves the HTTP Origin for origin-scope validation. Uses the explicit $override when provided; falls back to $originProvider otherwise. |
| [`checkOrigin()`](#csrf-checkorigin) | private | `bool` | Checks the resolved origin against the container's allowed_origins list. Returns true immediately when allowed_origins is empty (no restriction). |
| [`checkBoundOrigin()`](#csrf-checkboundorigin) | private | `bool` | Verifies the payload's bound origin against the current request origin. No-op (returns true) when the container has no 'origin' configured. When configured, both the stored and the resolved request origin must be present, normalized, and equal (constant-time comparison); a missing request origin is always rejected (strict fail-closed policy). |
| [`checkProof()`](#csrf-checkproof) | private | `bool` | Verifies a submitted _csrf_proof value against the container configuration. Transparent by design: a submitted proof is always verified (rejecting the request on mismatch), while a missing proof is only rejected when the container's 'require_proof' is true. A proof cannot be verified without the exact raw token it was issued for; passing $rawToken as null while a proof is required or submitted fails closed. |
| [`generateProof()`](#csrf-generateproof) | private | `string` | Computes the session-bound HMAC proof for a token. |
| [`encodeProofFields()`](#csrf-encodeprooffields) | private | `string` | Encodes proof fields unambiguously using 4-byte big-endian length prefixes. |
| [`normalizeOrigin()`](#csrf-normalizeorigin) | private | `string\|null` | Normalizes an HTTP origin to scheme://host[:port] form. Lowercases scheme and host, strips a trailing slash, and omits the port when it matches the scheme's default (443 for https, 80 for http). Only http/https schemes are accepted; anything else (or malformed input) normalizes to null. |
| [`deriveContainerKey()`](#csrf-derivecontainerkey) | private | `string` | Derive the per-container 32-byte AES-GCM encryption key with HKDF(SHA-256). |
| [`deriveProofKey()`](#csrf-deriveproofkey) | private | `string` | Derive the per-container 32-byte _csrf_proof HMAC key with HKDF(SHA-256). Uses a distinct HKDF info label from deriveContainerKey() so the proof key is cryptographically independent from the AES-GCM encryption key even though both are derived from the same base key (master or 'private_key'). |
| [`deriveKey()`](#csrf-derivekey) | private | `string` | Derive a purpose-scoped 32-byte key with HKDF(SHA-256). |
| [`makeAad()`](#csrf-makeaad) | private | `string` | Build Additional Authenticated Data (AAD) for AES-GCM. |
| [`encrypt()`](#csrf-encrypt) | private | `string` | AES-256-GCM encrypt with AAD. Returns base64(iv\|tag\|ciphertext). |
| [`decrypt()`](#csrf-decrypt) | private | `array\|null` | AES-256-GCM decrypt with AAD. Accepts base64(iv\|tag\|ciphertext). |
| [`debugValidate()`](#csrf-debugvalidate) | public | `array` | Debug variant of container-aware validation. - Works for any container id (including "default"). - Does NOT clear the token on success. - Never throws; always returns a detailed diagnostic array. Usage: $debug = $csrf->debugValidate($token); // default container $debug = $csrf->debugValidate($token, 'contactform_main'); // custom container $debug = $csrf->debugValidate($token, 'signup', $ip, $userAgent); Return structure: - ok (bool) : final validation result - reason (?string): high-level reason (ok, missing_token, decrypt_failed, ...) - containerId (string) : container id used - input (array) : raw input info (encrypted_present, ip_param, ua_param) - steps (array) : list of completed steps - config (array) : effective container config (bind_ip, bind_ua, prefix, bucketKey, pepper_set) - payload_raw (array) : decrypted payload (if decrypt succeeded) - state (array) : session state (token, iat) if present - expected (array) : expected token/ip/ua derived from state and config - actual (array) : actual token/ip/ua from payload - mismatch (array) : per-field match flags (only on payload_mismatch) - details (array) : extra details for some reasons (e.g. expired, container_mismatch) |

<details>
<summary><code>__construct()</code></summary>

#### `Csrf __construct()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L129)

```php
public function __construct(string $cipherKey, int $ttlSeconds, ?ClientContextProviderInterface $contextProvider, ?SessionBindingProviderInterface $sessionBindingProvider, ?OriginProviderInterface $originProvider)
```

| Param | Type | Description |
|---|---|---|
| `$cipherKey` | `string` | 32-byte key used for AES-256-GCM encryption. |
| `$ttlSeconds` | `int` | Token TTL (seconds). 0 disables expiration. |
| `$contextProvider` | `ClientContextProviderInterface\|null` | Optional client context provider (IP/UA). |
| `$sessionBindingProvider` | `SessionBindingProviderInterface\|null` | Optional session binding provider for _csrf_proof (default: native PHP session id). |
| `$originProvider` | `OriginProviderInterface\|null` | Optional origin provider. Defaults to $contextProvider when it also implements OriginProviderInterface, otherwise falls back to ServerGlobalClientContextProvider. |

| Throws | When |
|---|---|
| `\InvalidArgumentException` | If $cipherKey length is not exactly 32 bytes. |

</details>

<details>
<summary><code>withContainer()</code></summary>

#### `Csrf withContainer()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L159)

```php
public function withContainer(string $containerId, array $options): self
```

Configure/override options for a container ID. Merges, in order: built-in defaults < setDefaults() < $options.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | Container identifier (e.g., 'signup', 'profile'). |
| `$options` | `array` | See $containerOptions description. |

**Returns:** `$this`

| Throws | When |
|---|---|
| `\InvalidArgumentException` | If $options['private_key'] is set but not exactly 32 bytes. |

</details>

<details>
<summary><code>setDefaults()</code></summary>

#### `Csrf setDefaults()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L188)

```php
public function setDefaults(array $defaults): self
```

Registers global default options applied to every container. Sits between the library's built-in fallback values and any per-container options passed to withContainer(): CONTAINER_OPTION_DEFAULTS < $defaults < withContainer(). Also applies to container ids used without prior withContainer() registration at all (e.g. ad-hoc container ids resolved at request time).

| Param | Type | Description |
|---|---|---|
| `$defaults` | `array` | Same shape as withContainer()'s $options. |

**Returns:** `$this`

</details>

<details>
<summary><code>getContainerConfig()</code></summary>

#### `Csrf getContainerConfig()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L203)

```php
public function getContainerConfig(string $containerId): array
```

Returns the fully-resolved effective configuration for a container id — built-in defaults, app-registered defaults (setDefaults()), and any per-container override (withContainer()), merged in that order. Works even when the container was never explicitly registered.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |

**Returns:** `array{prefix: string, bind_ip: bool, bind_ua: bool, pepper: ?string, allowed_origins: list<string>, origin_mode: string, origin: ?string, require_proof: bool, private_key: ?string}`

</details>

<details>
<summary><code>getTtl()</code></summary>

#### `Csrf getTtl()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L210)

```php
public function getTtl(): int
```

**Returns:** `int` — TTL in seconds (0 means no expiry).

</details>

<details>
<summary><code>generate()</code></summary>

#### `Csrf generate()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L224)

```php
public function generate(?string $ip, ?string $userAgent): string
```

Generate an encrypted token for the default container.

| Param | Type | Description |
|---|---|---|
| `$ip` | `string\|null` | Optional client IP override. |
| `$userAgent` | `string\|null` | Optional User-Agent override. |

**Returns:** `string` — Encrypted token for the default container.

</details>

<details>
<summary><code>validate()</code></summary>

#### `Csrf validate()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L237)

```php
public function validate(?string $encrypted, ?string $ip, ?string $userAgent): bool
```

Validate an encrypted token for the default container.

| Param | Type | Description |
|---|---|---|
| `$encrypted` | `string\|null` | Encrypted token. |
| `$ip` | `string\|null` | Optional client IP override. |
| `$userAgent` | `string\|null` | Optional User-Agent override. |

**Returns:** `bool` — True if valid for the default container.

</details>

<details>
<summary><code>regenerate()</code></summary>

#### `Csrf regenerate()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L243)

```php
public function regenerate(): string
```

**Returns:** `string` — New encrypted token for the default container.

</details>

<details>
<summary><code>getExpiresIn()</code></summary>

#### `Csrf getExpiresIn()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L252)

```php
public function getExpiresIn(): ?int
```

**Returns:** `int\|null` — Seconds until expiry of the default container token; null if no token; 0 if expired; PHP_INT_MAX if TTL=0.

</details>

<details>
<summary><code>getLastPayload()</code></summary>

#### `Csrf getLastPayload()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L258)

```php
public function getLastPayload(): ?array
```

**Returns:** `array\|null` — Last generated/validated payload.

</details>

<details>
<summary><code>clear()</code></summary>

#### `Csrf clear()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L264)

```php
public function clear(): void
```

Clear the default container token state.

</details>

<details>
<summary><code>generateFor()</code></summary>

#### `Csrf generateFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L281)

```php
public function generateFor(string $containerId, ?string $ip, ?string $userAgent): string
```

Generate (or reuse unexpired) token for a container.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | Container identifier. |
| `$ip` | `string\|null` | Optional client IP override. |
| `$userAgent` | `string\|null` | Optional User-Agent override. |

**Returns:** `string` — Encrypted token.

| Throws | When |
|---|---|
| `\RuntimeException` | If the container's 'origin' is set but does not normalize to a valid http(s) origin. |

</details>

<details>
<summary><code>issueFor()</code></summary>

#### `Csrf issueFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L341)

```php
public function issueFor(string $containerId, ?string $ip, ?string $userAgent): CsrfPair
```

Generate a token together with its session-bound _csrf_proof, atomically. Unlike generateFor(), the proof is always computed here regardless of the container's 'require_proof' setting — that setting only controls whether validateFor()/validateCachedFor() reject a request missing the proof. Token and proof must always be refreshed together; never mix a token from one pair with a proof from another.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | Container identifier. |
| `$ip` | `string\|null` | Optional client IP override. |
| `$userAgent` | `string\|null` | Optional User-Agent override. |

**Returns:** [`CsrfPair`](#csrfpair) — Token and its matching proof (proof is null when the session binding cannot be resolved, e.g. no active session).

</details>

<details>
<summary><code>validateFor()</code></summary>

#### `Csrf validateFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L369)

```php
public function validateFor(string $containerId, ?string $encrypted, ?string $ip, ?string $userAgent, ?string $origin, ?string $proof): bool
```

Validate an encrypted token for a specific container.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | Container identifier. |
| `$encrypted` | `string\|null` | Encrypted token to validate. |
| `$ip` | `string\|null` | Optional client IP override. |
| `$userAgent` | `string\|null` | Optional User-Agent override. |
| `$origin` | `string\|null` | Optional HTTP Origin override. When null, resolved automatically via OriginProviderInterface if available. |
| `$proof` | `string\|null` | Submitted _csrf_proof value. When present, it is always verified; when absent, it is only required if the container's 'require_proof' is true. |

**Returns:** `bool` — True on success, false otherwise.

</details>

<details>
<summary><code>validateCachedFor()</code></summary>

#### `Csrf validateCachedFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L448)

```php
public function validateCachedFor(string $containerId, array $payload, ?string $ip, ?string $userAgent, ?string $origin, ?string $rawToken, ?string $proof): bool
```

Validate a cached payload for a specific container (no decrypt).

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | Container identifier. |
| `$payload` | `array` | Cached payload to check. |
| `$ip` | `string\|null` | Optional client IP override. |
| `$userAgent` | `string\|null` | Optional User-Agent override. |
| `$origin` | `string\|null` | Optional HTTP Origin override. |
| `$rawToken` | `string\|null` | The exact opaque encrypted token this cached payload was looked up by. Required to verify $proof; when omitted and a proof is required or submitted, validation fails closed. |
| `$proof` | `string\|null` | Submitted _csrf_proof value (see validateFor()). |

**Returns:** `bool` — True if matches session and not expired.

</details>

<details>
<summary><code>regenerateFor()</code></summary>

#### `Csrf regenerateFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L506)

```php
public function regenerateFor(string $containerId): string
```

Force new token for a container (clears previous state).

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |

**Returns:** `string` — New encrypted token.

</details>

<details>
<summary><code>getExpiresInFor()</code></summary>

#### `Csrf getExpiresInFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L519)

```php
public function getExpiresInFor(string $containerId): ?int
```

Remaining lifetime for a container.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |

**Returns:** `int\|null` — Seconds remaining, 0 if expired, null if no token, PHP_INT_MAX if TTL=0.

</details>

<details>
<summary><code>clearFor()</code></summary>

#### `Csrf clearFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L543)

```php
public function clearFor(string $containerId): void
```

Clear token for a container.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |

</details>

<details>
<summary><code>resolveContainer()</code></summary>

#### `Csrf resolveContainer()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L557)

```php
private function resolveContainer(string $containerId): array
```

Resolve session bucket and merged options for a container.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |

**Returns:** `array{bucketKey: string, cfg: array{prefix: string, bind_ip: bool, bind_ua: bool, pepper: ?string}}`

</details>

<details>
<summary><code>isExpired()</code></summary>

#### `Csrf isExpired()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L576)

```php
public function isExpired(?array $state): bool
```

Check if a given session state is expired.

| Param | Type | Description |
|---|---|---|
| `$state` | `array\|null` | — |

**Returns:** `bool` — True if expired/invalid.

</details>

<details>
<summary><code>resolveIp()</code></summary>

#### `Csrf resolveIp()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L593)

```php
private function resolveIp(?string $override): string
```

Resolve IP address using explicit override or context provider.

| Param | Type | Description |
|---|---|---|
| `$override` | `string\|null` | Explicit IP passed by caller (optional). |

**Returns:** `string` — Resolved IP address.

</details>

<details>
<summary><code>resolveUserAgent()</code></summary>

#### `Csrf resolveUserAgent()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L607)

```php
private function resolveUserAgent(?string $override): string
```

Resolve User-Agent using explicit override or context provider.

| Param | Type | Description |
|---|---|---|
| `$override` | `string\|null` | Explicit User-Agent passed by caller (optional). |

**Returns:** `string` — Resolved User-Agent.

</details>

<details>
<summary><code>resolveOrigin()</code></summary>

#### `Csrf resolveOrigin()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L624)

```php
private function resolveOrigin(?string $override): ?string
```

Resolves the HTTP Origin for origin-scope validation. Uses the explicit $override when provided; falls back to $originProvider otherwise.

| Param | Type | Description |
|---|---|---|
| `$override` | `string\|null` | Explicit origin passed by the caller. |

**Returns:** `string\|null` — Resolved origin or null.

</details>

<details>
<summary><code>checkOrigin()</code></summary>

#### `Csrf checkOrigin()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L642)

```php
private function checkOrigin(array $cfg, ?string $origin): bool
```

Checks the resolved origin against the container's allowed_origins list. Returns true immediately when allowed_origins is empty (no restriction).

| Param | Type | Description |
|---|---|---|
| `$cfg` | `array` | Resolved container configuration. |
| `$origin` | `string\|null` | Explicit origin override (null = auto-resolve). |

**Returns:** `bool` — True when origin is permitted.

</details>

<details>
<summary><code>checkBoundOrigin()</code></summary>

#### `Csrf checkBoundOrigin()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L667)

```php
private function checkBoundOrigin(array $cfg, array $payload, ?string $origin): bool
```

Verifies the payload's bound origin against the current request origin. No-op (returns true) when the container has no 'origin' configured. When configured, both the stored and the resolved request origin must be present, normalized, and equal (constant-time comparison); a missing request origin is always rejected (strict fail-closed policy).

| Param | Type | Description |
|---|---|---|
| `$cfg` | `array` | Resolved container configuration. |
| `$payload` | `array` | Decrypted token payload. |
| `$origin` | `string\|null` | Explicit origin override (null = auto-resolve). |

**Returns:** `bool` — True when the origin binding check passes.

</details>

<details>
<summary><code>checkProof()</code></summary>

#### `Csrf checkProof()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L699)

```php
private function checkProof(array $cfg, string $containerId, ?string $rawToken, ?string $proof): bool
```

Verifies a submitted _csrf_proof value against the container configuration. Transparent by design: a submitted proof is always verified (rejecting the request on mismatch), while a missing proof is only rejected when the container's 'require_proof' is true. A proof cannot be verified without the exact raw token it was issued for; passing $rawToken as null while a proof is required or submitted fails closed.

| Param | Type | Description |
|---|---|---|
| `$cfg` | `array` | Resolved container configuration. |
| `$containerId` | `string` | Container identifier. |
| `$rawToken` | `string\|null` | Exact opaque _csrf token the proof was issued for. |
| `$proof` | `string\|null` | Submitted _csrf_proof value. |

**Returns:** `bool` — True when the proof check passes.

</details>

<details>
<summary><code>generateProof()</code></summary>

#### `Csrf generateProof()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L731)

```php
private function generateProof(string $containerId, string $csrfToken, string $sessionBinding, ?string $pepper, ?string $privateKey): string
```

Computes the session-bound HMAC proof for a token.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | Container identifier. |
| `$csrfToken` | `string` | The exact opaque encrypted _csrf token value. |
| `$sessionBinding` | `string` | Current session-bound value (see SessionBindingProviderInterface). |
| `$pepper` | `string\|null` | Container's optional HKDF pepper (kept in sync with the encryption key derivation for the same container). |
| `$privateKey` | `string\|null` | Container's optional dedicated key (see 'private_key'). |

**Returns:** `string` — Base64URL-encoded (unpadded) HMAC-SHA256 proof.

</details>

<details>
<summary><code>encodeProofFields()</code></summary>

#### `Csrf encodeProofFields()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L759)

```php
private function encodeProofFields(array $fields): string
```

Encodes proof fields unambiguously using 4-byte big-endian length prefixes.

| Param | Type | Description |
|---|---|---|
| `$fields` | `list<string>` | Fields to encode, in order. |

**Returns:** `string` — Encoded byte string.

</details>

<details>
<summary><code>normalizeOrigin()</code></summary>

#### `Csrf normalizeOrigin()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L780)

```php
private function normalizeOrigin(?string $origin): ?string
```

Normalizes an HTTP origin to scheme://host[:port] form. Lowercases scheme and host, strips a trailing slash, and omits the port when it matches the scheme's default (443 for https, 80 for http). Only http/https schemes are accepted; anything else (or malformed input) normalizes to null.

| Param | Type | Description |
|---|---|---|
| `$origin` | `string\|null` | Raw origin value. |

**Returns:** `string\|null` — Normalized origin, or null when invalid/absent.

</details>

<details>
<summary><code>deriveContainerKey()</code></summary>

#### `Csrf deriveContainerKey()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L815)

```php
private function deriveContainerKey(string $containerId, ?string $pepper, ?string $privateKey): string
```

Derive the per-container 32-byte AES-GCM encryption key with HKDF(SHA-256).

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |
| `$pepper` | `string\|null` | Binary salt for HKDF-Extract; optional. |
| `$privateKey` | `string\|null` | Container's optional dedicated key (see 'private_key'); when set, used instead of the master $cipherKey. |

**Returns:** `string` — 32-byte binary key.

</details>

<details>
<summary><code>deriveProofKey()</code></summary>

#### `Csrf deriveProofKey()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L833)

```php
private function deriveProofKey(string $containerId, ?string $pepper, ?string $privateKey): string
```

Derive the per-container 32-byte _csrf_proof HMAC key with HKDF(SHA-256). Uses a distinct HKDF info label from deriveContainerKey() so the proof key is cryptographically independent from the AES-GCM encryption key even though both are derived from the same base key (master or 'private_key').

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |
| `$pepper` | `string\|null` | Binary salt for HKDF-Extract; optional. |
| `$privateKey` | `string\|null` | Container's optional dedicated key (see 'private_key'); when set, used instead of the master $cipherKey. |

**Returns:** `string` — 32-byte binary key.

</details>

<details>
<summary><code>deriveKey()</code></summary>

#### `Csrf deriveKey()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L849)

```php
private function deriveKey(string $containerId, ?string $pepper, string $purpose, ?string $privateKey): string
```

Derive a purpose-scoped 32-byte key with HKDF(SHA-256).

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |
| `$pepper` | `string\|null` | Binary salt for HKDF-Extract; optional. |
| `$purpose` | `string` | HKDF info label prefix providing domain separation between different key purposes (e.g. 'csrf', 'csrf-proof'). |
| `$privateKey` | `string\|null` | Base key to derive from instead of the master $cipherKey, when the container has its own 'private_key' configured. |

**Returns:** `string` — 32-byte binary key.

</details>

<details>
<summary><code>makeAad()</code></summary>

#### `Csrf makeAad()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L875)

```php
private function makeAad(string $containerId, string $prefix): string
```

Build Additional Authenticated Data (AAD) for AES-GCM.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |
| `$prefix` | `string` | — |

**Returns:** `string`

</details>

<details>
<summary><code>encrypt()</code></summary>

#### `Csrf encrypt()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L888)

```php
private function encrypt(string $key, array $data, string $aad): string
```

AES-256-GCM encrypt with AAD. Returns base64(iv|tag|ciphertext).

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | 32-byte binary key. |
| `$data` | `array` | Payload to encrypt. |
| `$aad` | `string` | Additional authenticated data. |

**Returns:** `string` — Base64-encoded token.

</details>

<details>
<summary><code>decrypt()</code></summary>

#### `Csrf decrypt()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L916)

```php
private function decrypt(string $key, string $input, string $aad): ?array
```

AES-256-GCM decrypt with AAD. Accepts base64(iv|tag|ciphertext).

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | 32-byte binary key. |
| `$input` | `string` | Base64 token. |
| `$aad` | `string` | Additional authenticated data. |

**Returns:** `array\|null` — Decrypted payload, or null on failure.

</details>

<details>
<summary><code>debugValidate()</code></summary>

#### `Csrf debugValidate()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Csrf.php#L970)

```php
public function debugValidate(?string $encrypted, ?string $containerId, ?string $ip, ?string $userAgent, ?string $origin, ?string $proof): array
```

Debug variant of container-aware validation. - Works for any container id (including "default"). - Does NOT clear the token on success. - Never throws; always returns a detailed diagnostic array. Usage: $debug = $csrf->debugValidate($token);                          // default container $debug = $csrf->debugValidate($token, 'contactform_main');      // custom container $debug = $csrf->debugValidate($token, 'signup', $ip, $userAgent); Return structure: - ok          (bool)   : final validation result - reason      (?string): high-level reason (ok, missing_token, decrypt_failed, ...) - containerId (string) : container id used - input       (array)  : raw input info (encrypted_present, ip_param, ua_param) - steps       (array)  : list of completed steps - config      (array)  : effective container config (bind_ip, bind_ua, prefix, bucketKey, pepper_set) - payload_raw (array)  : decrypted payload (if decrypt succeeded) - state       (array)  : session state (token, iat) if present - expected    (array)  : expected token/ip/ua derived from state and config - actual      (array)  : actual token/ip/ua from payload - mismatch    (array)  : per-field match flags (only on payload_mismatch) - details     (array)  : extra details for some reasons (e.g. expired, container_mismatch)

| Param | Type | Description |
|---|---|---|
| `$encrypted` | `?string` | — |
| `$containerId` | `?string` | — |
| `$ip` | `?string` | — |
| `$userAgent` | `?string` | — |
| `$origin` | `?string` | — |
| `$proof` | `?string` | — |

**Returns:** `array`

</details>

## `CsrfCacheWrapper`

*class* — `rafalmasiarek\Csrf\CsrfCacheWrapper` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfCacheWrapper.php#L13)

Cache wrapper for CSRF validation. Caches decrypted payloads keyed by a composite "<container>|<token>" string. On cache hit, validates IP/UA/TTL quickly without decryption.

**Depends on:** [`Csrf`](#csrf), [`CsrfStorageInterface`](#csrfstorageinterface)

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$core` | [`Csrf`](#csrf) | private | — |
| `$cache` | [`CsrfStorageInterface`](#csrfstorageinterface) | private | — |
| `$readOnly` | `bool` | private | — |
| `$lastCacheDebug` | `array<string, mixed>\|null` | private | Last cache debug info (for diagnostics only). Example structure: [ 'op' => 'generate'\|'validate', 'container' => 'default'\|'<id>', 'cache_key' => '<composite-key>', 'hit' => bool, // validate only 'fast_path' => bool, // validate only (validateCachedFor() success) 'stored' => bool\|null, // whether payload was stored after core validate 'result' => bool\|null, // validate result 'read_only' => bool, ] |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#csrfcachewrapper-__construct) | public | — | — |
| [`getLastCacheDebug()`](#csrfcachewrapper-getlastcachedebug) | public | `array<string, mixed>\|null` | Return debug info for the last cache operation (generate/validate). |
| [`generate()`](#csrfcachewrapper-generate) | public | `string` | Backwards-compat: default container. |
| [`validate()`](#csrfcachewrapper-validate) | public | `bool` | Backwards-compat: default container. |
| [`generateFor()`](#csrfcachewrapper-generatefor) | public | `string` | Generate and cache for container. |
| [`issueFor()`](#csrfcachewrapper-issuefor) | public | [`CsrfPair`](#csrfpair) | Issue a token/proof pair and cache the token's payload, for container. |
| [`validateFor()`](#csrfcachewrapper-validatefor) | public | `bool` | Validate with cache fast-path for container. |
| [`removeCached()`](#csrfcachewrapper-removecached) | public | `void` | Remove a cached entry (optional helper). |
| [`composeKey()`](#csrfcachewrapper-composekey) | private | `string` | Compose composite cache key. |

<details>
<summary><code>__construct()</code></summary>

#### `CsrfCacheWrapper __construct()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfCacheWrapper.php#L38)

```php
public function __construct(Csrf $core, CsrfStorageInterface $cache, bool $readOnly)
```

| Param | Type | Description |
|---|---|---|
| `$core` | [`Csrf`](#csrf) | — |
| `$cache` | [`CsrfStorageInterface`](#csrfstorageinterface) | — |
| `$readOnly` | `bool` | — |

</details>

<details>
<summary><code>getLastCacheDebug()</code></summary>

#### `CsrfCacheWrapper getLastCacheDebug()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfCacheWrapper.php#L50)

```php
public function getLastCacheDebug(): ?array
```

Return debug info for the last cache operation (generate/validate).

**Returns:** `array<string, mixed>\|null`

</details>

<details>
<summary><code>generate()</code></summary>

#### `CsrfCacheWrapper generate()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfCacheWrapper.php#L56)

```php
public function generate(): string
```

Backwards-compat: default container.

**Returns:** `string`

</details>

<details>
<summary><code>validate()</code></summary>

#### `CsrfCacheWrapper validate()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfCacheWrapper.php#L62)

```php
public function validate(string $token): bool
```

Backwards-compat: default container.

| Param | Type | Description |
|---|---|---|
| `$token` | `string` | — |

**Returns:** `bool`

</details>

<details>
<summary><code>generateFor()</code></summary>

#### `CsrfCacheWrapper generateFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfCacheWrapper.php#L73)

```php
public function generateFor(string $containerId): string
```

Generate and cache for container.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |

**Returns:** `string`

</details>

<details>
<summary><code>issueFor()</code></summary>

#### `CsrfCacheWrapper issueFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfCacheWrapper.php#L104)

```php
public function issueFor(string $containerId): CsrfPair
```

Issue a token/proof pair and cache the token's payload, for container.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |

**Returns:** [`CsrfPair`](#csrfpair)

</details>

<details>
<summary><code>validateFor()</code></summary>

#### `CsrfCacheWrapper validateFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfCacheWrapper.php#L138)

```php
public function validateFor(string $containerId, string $token, ?string $proof): bool
```

Validate with cache fast-path for container.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |
| `$token` | `string` | — |
| `$proof` | `string\|null` | Submitted _csrf_proof value (see Csrf::validateFor()). |

**Returns:** `bool`

</details>

<details>
<summary><code>removeCached()</code></summary>

#### `CsrfCacheWrapper removeCached()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfCacheWrapper.php#L206)

```php
public function removeCached(string $containerId, string $token): void
```

Remove a cached entry (optional helper).

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |
| `$token` | `string` | — |

</details>

<details>
<summary><code>composeKey()</code></summary>

#### `CsrfCacheWrapper composeKey()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfCacheWrapper.php#L212)

```php
private function composeKey(string $containerId, string $token): string
```

Compose composite cache key.

| Param | Type | Description |
|---|---|---|
| `$containerId` | `string` | — |
| `$token` | `string` | — |

**Returns:** `string`

</details>

## `CsrfPair`

*final readonly class* — `rafalmasiarek\Csrf\CsrfPair` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfPair.php#L15)

An atomically issued CSRF token and its matching session-bound proof. The token and proof are always refreshed together — never mix a token from one pair with a proof from another.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#csrfpair-__construct) | public | — | — |

<details>
<summary><code>__construct()</code></summary>

#### `CsrfPair __construct()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfPair.php#L22)

```php
public function __construct(string $token, ?string $proof)
```

| Param | Type | Description |
|---|---|---|
| `$token` | `string` | The encrypted _csrf token value. |
| `$proof` | `string\|null` | The _csrf_proof value, or null when the session binding could not be resolved. |

</details>

## `CsrfStorageInterface`

*interface* — `rafalmasiarek\Csrf\CsrfStorageInterface` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfStorageInterface.php#L5)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`store()`](#csrfstorageinterface-store) | public | `void` | Store a CSRF token and its associated payload. |
| [`fetch()`](#csrfstorageinterface-fetch) | public | `array\|null` | Fetch the payload associated with a CSRF token. |
| [`remove()`](#csrfstorageinterface-remove) | public | `void` | Remove a CSRF token and its associated payload. |

<details>
<summary><code>store()</code></summary>

#### `CsrfStorageInterface store()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfStorageInterface.php#L13)

```php
public function store(string $encryptedToken, array $payload): void
```

Store a CSRF token and its associated payload.

| Param | Type | Description |
|---|---|---|
| `$encryptedToken` | `string` | The encrypted CSRF token. |
| `$payload` | `array` | The payload associated with the CSRF token. |

</details>

<details>
<summary><code>fetch()</code></summary>

#### `CsrfStorageInterface fetch()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfStorageInterface.php#L21)

```php
public function fetch(string $encryptedToken): ?array
```

Fetch the payload associated with a CSRF token.

| Param | Type | Description |
|---|---|---|
| `$encryptedToken` | `string` | The encrypted CSRF token. |

**Returns:** `array\|null` — The payload if found, null otherwise.

</details>

<details>
<summary><code>remove()</code></summary>

#### `CsrfStorageInterface remove()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/CsrfStorageInterface.php#L28)

```php
public function remove(string $encryptedToken): void
```

Remove a CSRF token and its associated payload.

| Param | Type | Description |
|---|---|---|
| `$encryptedToken` | `string` | The encrypted CSRF token to remove. |

</details>

## `FileStorage`

*class* — `rafalmasiarek\Csrf\FileStorage` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/FileStorage.php#L11)

File-based CsrfStorageInterface. Stores entries under hashed filenames to avoid leaking token information.

implements [`CsrfStorageInterface`](#csrfstorageinterface)

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$dir` | `string` | private | — |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#filestorage-__construct) | public | — | — |
| [`store()`](#filestorage-store) | public | `void` | — |
| [`fetch()`](#filestorage-fetch) | public | `?array` | — |
| [`remove()`](#filestorage-remove) | public | `void` | — |
| [`pathFor()`](#filestorage-pathfor) | private | `string` | — |

<details>
<summary><code>__construct()</code></summary>

#### `FileStorage __construct()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/FileStorage.php#L18)

```php
public function __construct(string $dir)
```

| Param | Type | Description |
|---|---|---|
| `$dir` | `string` | Directory to store cache files (must be writable). |

</details>

<details>
<summary><code>store()</code></summary>

#### `FileStorage store()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/FileStorage.php#L29)

```php
public function store(string $encryptedToken, array $payload): void
```

| Param | Type | Description |
|---|---|---|
| `$encryptedToken` | `string` | — |
| `$payload` | `array` | — |

</details>

<details>
<summary><code>fetch()</code></summary>

#### `FileStorage fetch()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/FileStorage.php#L36)

```php
public function fetch(string $encryptedToken): ?array
```

| Param | Type | Description |
|---|---|---|
| `$encryptedToken` | `string` | — |

**Returns:** `?array`

</details>

<details>
<summary><code>remove()</code></summary>

#### `FileStorage remove()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/FileStorage.php#L47)

```php
public function remove(string $encryptedToken): void
```

| Param | Type | Description |
|---|---|---|
| `$encryptedToken` | `string` | — |

</details>

<details>
<summary><code>pathFor()</code></summary>

#### `FileStorage pathFor()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/FileStorage.php#L55)

```php
private function pathFor(string $key): string
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |

**Returns:** `string`

</details>

## `CsrfBlade`

*final class* — `rafalmasiarek\Csrf\Helpers\Blade\CsrfBlade` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Helpers/Blade/CsrfBlade.php#L15)

Blade helper for registering a @csrfField('container') directive. Usage: \rafalmasiarek\Csrf\Helpers\Blade\CsrfBlade::register($bladeCompiler, $csrf);

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`register()`](#csrfblade-register) | public static | `void` | — |

<details>
<summary><code>register()</code></summary>

#### `CsrfBlade register()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Helpers/Blade/CsrfBlade.php#L23)

```php
public static function register(object $bladeCompiler, Csrf $csrf, string $defaultContainer, string $inputName): void
```

| Param | Type | Description |
|---|---|---|
| `$bladeCompiler` | `object` | Instance of Illuminate\View\Compilers\BladeCompiler |
| `$csrf` | [`Csrf`](#csrf) | — |
| `$defaultContainer` | `string` | — |
| `$inputName` | `string` | — |

</details>

## `HtmlHelper`

*final class* — `rafalmasiarek\Csrf\Helpers\HtmlHelper` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Helpers/HtmlHelper.php#L12)

Generic HTML helper for rendering CSRF inputs.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`input()`](#htmlhelper-input) | public static | `string` | Render hidden inputs for CSRF protection. When a non-default container is used, emits a second hidden input (_csrf_container) so the server-side middleware knows which container to validate against. Without it, the middleware falls back to the "default" container and validation always fails for named containers. Transparently issues the token together with its _csrf_proof (see Csrf::issueFor()) and emits a third hidden input (_csrf_proof) whenever a proof is available (i.e. a session is active). No template changes are required to start benefiting from it; it has no effect on validation unless the receiving container sets 'require_proof'. |
| [`token()`](#htmlhelper-token) | public static | `string` | Returns the raw encrypted CSRF token value for a container, without wrapping it in an HTML input (e.g. for embedding in a <meta> tag or passing to client-side JavaScript). Does not compute or expose a proof. |

<details>
<summary><code>input()</code></summary>

#### `HtmlHelper input()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Helpers/HtmlHelper.php#L40)

```php
public static function input(Csrf $csrf, string $containerId, string $inputName, ?string $ip, ?string $userAgent): string
```

Render hidden inputs for CSRF protection. When a non-default container is used, emits a second hidden input (_csrf_container) so the server-side middleware knows which container to validate against. Without it, the middleware falls back to the "default" container and validation always fails for named containers. Transparently issues the token together with its _csrf_proof (see Csrf::issueFor()) and emits a third hidden input (_csrf_proof) whenever a proof is available (i.e. a session is active). No template changes are required to start benefiting from it; it has no effect on validation unless the receiving container sets 'require_proof'.

| Param | Type | Description |
|---|---|---|
| `$csrf` | [`Csrf`](#csrf) | — |
| `$containerId` | `string` | Container name (default: "default"). |
| `$inputName` | `string` | Input field name for the token (default: "_csrf"). |
| `$ip` | `string\|null` | Optional client IP override. Pass this whenever the caller already resolves the real client IP itself (e.g. behind a trusted proxy/CDN) — otherwise bind_ip validates against the proxy's address instead of the visitor's, and a validateFor() call that does pass the real IP will never match a token issued without it. |
| `$userAgent` | `string\|null` | Optional User-Agent override. |

**Returns:** `string` — HTML string, already escaped.

</details>

<details>
<summary><code>token()</code></summary>

#### `HtmlHelper token()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Helpers/HtmlHelper.php#L77)

```php
public static function token(Csrf $csrf, string $containerId, ?string $ip, ?string $userAgent): string
```

Returns the raw encrypted CSRF token value for a container, without wrapping it in an HTML input (e.g. for embedding in a <meta> tag or passing to client-side JavaScript). Does not compute or expose a proof.

| Param | Type | Description |
|---|---|---|
| `$csrf` | [`Csrf`](#csrf) | — |
| `$containerId` | `string` | Container name (default: "default"). |
| `$ip` | `string\|null` | Optional client IP override (see input()). |
| `$userAgent` | `string\|null` | Optional User-Agent override. |

**Returns:** `string` — Encrypted token value (not HTML-escaped).

</details>

## `CsrfExtension`

*final class* — `rafalmasiarek\Csrf\Helpers\Plates\CsrfExtension` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Helpers/Plates/CsrfExtension.php#L14)

Plates extension to expose csrf_token() and csrf_field().

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`register()`](#csrfextension-register) | public static | `void` | — |

<details>
<summary><code>register()</code></summary>

#### `CsrfExtension register()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Helpers/Plates/CsrfExtension.php#L16)

```php
public static function register(Engine $engine, Csrf $csrf, string $defaultContainer, string $inputName): void
```

| Param | Type | Description |
|---|---|---|
| `$engine` | `Engine` | — |
| `$csrf` | [`Csrf`](#csrf) | — |
| `$defaultContainer` | `string` | — |
| `$inputName` | `string` | — |

</details>

## `CsrfExtension`

*final class* — `rafalmasiarek\Csrf\Helpers\Twig\CsrfExtension` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Helpers/Twig/CsrfExtension.php#L15)

Twig extension providing {{ csrf_field('container')|raw }}.

extends `AbstractExtension`

**Depends on:** [`Csrf`](#csrf)

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$csrf` | [`Csrf`](#csrf) | private | — |
| `$defaultContainer` | `string` | private | — |
| `$inputName` | `string` | private | — |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#csrfextension-__construct) | public | — | — |
| [`getFunctions()`](#csrfextension-getfunctions) | public | `array` | — |

<details>
<summary><code>__construct()</code></summary>

#### `CsrfExtension __construct()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Helpers/Twig/CsrfExtension.php#L21)

```php
public function __construct(Csrf $csrf, string $defaultContainer, string $inputName)
```

| Param | Type | Description |
|---|---|---|
| `$csrf` | [`Csrf`](#csrf) | — |
| `$defaultContainer` | `string` | — |
| `$inputName` | `string` | — |

</details>

<details>
<summary><code>getFunctions()</code></summary>

#### `CsrfExtension getFunctions()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/Helpers/Twig/CsrfExtension.php#L28)

```php
public function getFunctions(): array
```

**Returns:** `array`

</details>

## `MysqlStorage`

*class* — `rafalmasiarek\Csrf\MysqlStorage` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/MysqlStorage.php#L23)

MySQL-based implementation of CsrfStorageInterface. Schema (example): CREATE TABLE csrf_cache ( token_hash VARCHAR(64) PRIMARY KEY, payload    JSON NOT NULL, created_at DATETIME NOT NULL ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4; Notes: - We hash whatever key we get. For multi-container, pass a composite key like "<container>|<token>" to avoid cross-container collisions.

implements [`CsrfStorageInterface`](#csrfstorageinterface)

**Depends on:** `PDO`

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$pdo` | `PDO` | private | — |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#mysqlstorage-__construct) | public | — | — |
| [`store()`](#mysqlstorage-store) | public | `void` | — |
| [`fetch()`](#mysqlstorage-fetch) | public | `?array` | — |
| [`remove()`](#mysqlstorage-remove) | public | `void` | — |

<details>
<summary><code>__construct()</code></summary>

#### `MysqlStorage __construct()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/MysqlStorage.php#L27)

```php
public function __construct(PDO $pdo)
```

| Param | Type | Description |
|---|---|---|
| `$pdo` | `PDO` | — |

</details>

<details>
<summary><code>store()</code></summary>

#### `MysqlStorage store()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/MysqlStorage.php#L33)

```php
public function store(string $key, array $payload): void
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |
| `$payload` | `array` | — |

</details>

<details>
<summary><code>fetch()</code></summary>

#### `MysqlStorage fetch()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/MysqlStorage.php#L42)

```php
public function fetch(string $key): ?array
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |

**Returns:** `?array`

</details>

<details>
<summary><code>remove()</code></summary>

#### `MysqlStorage remove()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/MysqlStorage.php#L51)

```php
public function remove(string $key): void
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |

</details>

## `OriginMatcher`

*final class* — `rafalmasiarek\Csrf\OriginMatcher` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/OriginMatcher.php#L21)

Matches an HTTP Origin value against a list of allowed patterns. Pattern syntax: - Full origin  : "https://example.com"  — scheme + host must match exactly. - Scheme-free  : "example.com"          — only host[:port] is compared; any scheme is accepted. - Wildcard     : "https://*.example.com" or "*.example.com" Each * matches exactly one subdomain label (no dots). "https://*.example.com" matches "https://www.example.com" but NOT "https://a.b.example.com".

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`matches()`](#originmatcher-matches) | public static | `bool` | Checks whether $origin is permitted by $patterns under the given $mode. |
| [`patternMatches()`](#originmatcher-patternmatches) | private static | `bool` | Tests a single pattern against the actual origin. |
| [`patternToRegex()`](#originmatcher-patterntoregex) | private static | `string` | Converts a wildcard origin pattern to a PCRE regex. Each * is expanded to [^.]+ (one subdomain label, no dots). |

<details>
<summary><code>matches()</code></summary>

#### `OriginMatcher matches()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/OriginMatcher.php#L34)

```php
public static function matches(?string $origin, array $patterns, string $mode): bool
```

Checks whether $origin is permitted by $patterns under the given $mode.

| Param | Type | Description |
|---|---|---|
| `$origin` | `string\|null` | Actual origin from the request (may be null when the browser did not send an Origin/Referer header). |
| `$patterns` | `list<string>` | Allowed origin patterns (empty = no restriction). |
| `$mode` | `string` | 'strict' — null origin is rejected. 'lenient' — null origin is accepted (default). |

**Returns:** `bool` — True when the origin is permitted.

</details>

<details>
<summary><code>patternMatches()</code></summary>

#### `OriginMatcher patternMatches()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/OriginMatcher.php#L61)

```php
private static function patternMatches(string $pattern, string $origin): bool
```

Tests a single pattern against the actual origin.

| Param | Type | Description |
|---|---|---|
| `$pattern` | `string` | Allowed-origin pattern (may include * and optional scheme). |
| `$origin` | `string` | Actual request origin. |

**Returns:** `bool`

</details>

<details>
<summary><code>patternToRegex()</code></summary>

#### `OriginMatcher patternToRegex()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/OriginMatcher.php#L90)

```php
private static function patternToRegex(string $pattern): string
```

Converts a wildcard origin pattern to a PCRE regex. Each * is expanded to [^.]+ (one subdomain label, no dots).

| Param | Type | Description |
|---|---|---|
| `$pattern` | `string` | Origin pattern potentially containing *. |

**Returns:** `string` — PCRE regex with delimiters.

</details>

## `OriginProviderInterface`

*interface* — `rafalmasiarek\Csrf\OriginProviderInterface` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/OriginProviderInterface.php#L17)

Provides the HTTP Origin for CSRF origin-scope validation and origin binding. Pass an implementation as the 5th constructor argument to Csrf to enable automatic origin resolution for allowed_origins checks and 'origin' binding in Csrf::validateFor(). ServerGlobalClientContextProvider implements this interface (alongside ClientContextProviderInterface) and is used by default.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`getOrigin()`](#originproviderinterface-getorigin) | public | `string\|null` | Returns the effective HTTP Origin of the current request. Implementations should prefer the Origin header and fall back to extracting scheme://host[:port] from the Referer header. Return null when neither header is present. |

<details>
<summary><code>getOrigin()</code></summary>

#### `OriginProviderInterface getOrigin()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/OriginProviderInterface.php#L28)

```php
public function getOrigin(): ?string
```

Returns the effective HTTP Origin of the current request. Implementations should prefer the Origin header and fall back to extracting scheme://host[:port] from the Referer header. Return null when neither header is present.

**Returns:** `string\|null` — Normalised origin (e.g. "https://example.com") or null.

</details>

## `PhpSessionBindingProvider`

*final class* — `rafalmasiarek\Csrf\PhpSessionBindingProvider` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/PhpSessionBindingProvider.php#L17)

Default session binding provider backed by the native PHP session id. Suitable when the application relies on native PHP sessions for authentication. Applications that decouple their logical login session from the PHP session id (e.g. JWT-backed sessions) should provide a custom SessionBindingProviderInterface implementation instead.

implements [`SessionBindingProviderInterface`](#sessionbindingproviderinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`getSessionBinding()`](#phpsessionbindingprovider-getsessionbinding) | public | `string` | Returns the current native PHP session id. |

<details>
<summary><code>getSessionBinding()</code></summary>

#### `PhpSessionBindingProvider getSessionBinding()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/PhpSessionBindingProvider.php#L24)

```php
public function getSessionBinding(): string
```

Returns the current native PHP session id.

**Returns:** `string` — Session id (empty string when no session is active).

</details>

## `RedisStorage`

*class* — `rafalmasiarek\Csrf\RedisStorage` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/RedisStorage.php#L11)

Redis-based CsrfStorageInterface. Uses PHP Redis extension (\Redis) with simple set/get/del operations.

implements [`CsrfStorageInterface`](#csrfstorageinterface)

**Depends on:** `\Redis`

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$redis` | `\Redis` | private | — |
| `$prefix` | `string` | private | — |
| `$ttl` | `int` | private | — |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#redisstorage-__construct) | public | — | — |
| [`store()`](#redisstorage-store) | public | `void` | — |
| [`fetch()`](#redisstorage-fetch) | public | `?array` | — |
| [`remove()`](#redisstorage-remove) | public | `void` | — |

<details>
<summary><code>__construct()</code></summary>

#### `RedisStorage __construct()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/RedisStorage.php#L22)

```php
public function __construct(\Redis $redis, string $prefix, int $ttl)
```

| Param | Type | Description |
|---|---|---|
| `$redis` | `\Redis` | Connected Redis client. |
| `$prefix` | `string` | Key prefix (default: "csrf:"). |
| `$ttl` | `int` | TTL for cache entries in seconds (default: 900). |

</details>

<details>
<summary><code>store()</code></summary>

#### `RedisStorage store()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/RedisStorage.php#L30)

```php
public function store(string $key, array $payload): void
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |
| `$payload` | `array` | — |

</details>

<details>
<summary><code>fetch()</code></summary>

#### `RedisStorage fetch()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/RedisStorage.php#L37)

```php
public function fetch(string $key): ?array
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |

**Returns:** `?array`

</details>

<details>
<summary><code>remove()</code></summary>

#### `RedisStorage remove()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/RedisStorage.php#L45)

```php
public function remove(string $key): void
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |

</details>

## `ServerGlobalClientContextProvider`

*final class* — `rafalmasiarek\Csrf\ServerGlobalClientContextProvider` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ServerGlobalClientContextProvider.php#L15)

Default client context provider that reads IP, User-Agent, and Origin from $_SERVER. Implements both ClientContextProviderInterface and OriginProviderInterface so that origin-scope validation works out of the box without any extra configuration.

implements [`ClientContextProviderInterface`](#clientcontextproviderinterface), [`OriginProviderInterface`](#originproviderinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`getIp()`](#serverglobalclientcontextprovider-getip) | public | `string` | Returns the client IP address from REMOTE_ADDR. |
| [`getUserAgent()`](#serverglobalclientcontextprovider-getuseragent) | public | `string` | Returns the HTTP User-Agent header value. |
| [`getOrigin()`](#serverglobalclientcontextprovider-getorigin) | public | `string\|null` | Returns the effective HTTP Origin of the current request. Prefers the Origin header. Falls back to extracting scheme://host[:port] from the Referer header when Origin is absent. |

<details>
<summary><code>getIp()</code></summary>

#### `ServerGlobalClientContextProvider getIp()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ServerGlobalClientContextProvider.php#L22)

```php
public function getIp(): string
```

Returns the client IP address from REMOTE_ADDR.

**Returns:** `string` — IP address or empty string when unavailable.

</details>

<details>
<summary><code>getUserAgent()</code></summary>

#### `ServerGlobalClientContextProvider getUserAgent()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ServerGlobalClientContextProvider.php#L34)

```php
public function getUserAgent(): string
```

Returns the HTTP User-Agent header value.

**Returns:** `string` — User-Agent string or empty string when unavailable.

</details>

<details>
<summary><code>getOrigin()</code></summary>

#### `ServerGlobalClientContextProvider getOrigin()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/ServerGlobalClientContextProvider.php#L49)

```php
public function getOrigin(): ?string
```

Returns the effective HTTP Origin of the current request. Prefers the Origin header. Falls back to extracting scheme://host[:port] from the Referer header when Origin is absent.

**Returns:** `string\|null` — Normalised origin or null when neither header is present.

</details>

## `SessionBindingProviderInterface`

*interface* — `rafalmasiarek\Csrf\SessionBindingProviderInterface` · [source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/SessionBindingProviderInterface.php#L17)

Provides a value that changes with every authenticated session, used to bind the _csrf_proof HMAC to the current login/session context. Implementations must never return a static account identifier (user id, email, username) — the returned value must change whenever the login session is regenerated (e.g. on login, privilege elevation, or logout).

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`getSessionBinding()`](#sessionbindingproviderinterface-getsessionbinding) | public | `string` | Returns the current session-bound value used as HMAC proof input. The value is only ever used as an HMAC input and is never exposed in plaintext inside the _csrf_proof value. |

<details>
<summary><code>getSessionBinding()</code></summary>

#### `SessionBindingProviderInterface getSessionBinding()`

[source](https://github.com/rafalmasiarek/php-csrf/blob/main/src/SessionBindingProviderInterface.php#L27)

```php
public function getSessionBinding(): string
```

Returns the current session-bound value used as HMAC proof input. The value is only ever used as an HMAC input and is never exposed in plaintext inside the _csrf_proof value.

**Returns:** `string` — Opaque, session-dependent binding value.

</details>




<!-- references -->

[repo_link]: https://github.com/rafalmasiarek/php-csrf
