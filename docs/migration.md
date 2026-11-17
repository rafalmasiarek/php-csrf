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

