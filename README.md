# PHP CSRF — Encrypted, Container‑Aware Tokens

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

- **PHP requirement raised to `>=8.1`** (`CsrfPair` uses readonly properties). This is a
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

MIT
