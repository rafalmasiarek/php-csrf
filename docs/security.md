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
