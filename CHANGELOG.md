# Changelog

All notable changes to this project are documented in this file, starting with `1.5.0`.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
does not strictly follow SemVer for pre-1.0-style breaking changes across minor versions — see
each entry's "Breaking" notes.

## [1.5.0] — 2026-09-16

### Added

- **Origin binding** (`origin` container option): a trusted origin is embedded in the encrypted
  token payload at generation time and enforced (constant-time comparison, fail-closed on a
  missing request origin) against the resolved request origin at validation time. Independent
  from, and complementary to, the existing `allowed_origins` whitelist.
- **Session-bound HMAC proof** (`_csrf_proof`): `Csrf::issueFor()` returns a `CsrfPair` (token +
  proof). The proof is an HMAC-SHA256 over the exact token, container id, and a session-bound
  value, keyed by a proof key derived independently from the AES-GCM encryption key via HKDF
  domain separation (`csrf-proof:<container>` vs. `csrf:<container>`). Verification is
  transparent — a submitted proof is always checked; a *missing* proof is only rejected when
  the new `require_proof` container option is `true` (default `false`).
- `SessionBindingProviderInterface`, with a default implementation `PhpSessionBindingProvider`
  backed by `session_id()`. Injectable as `Csrf`'s 4th constructor argument.
- `CsrfPair`: immutable (`readonly`) value object returned by `issueFor()`.
- `Csrf::issueFor()` and `CsrfCacheWrapper::issueFor()`: atomic token+proof issuance, including
  cache-store passthrough on the wrapper.
- `HtmlHelper::token()`: returns the raw encrypted token value without HTML wrapping (for
  embedding in a `<meta>` tag or passing to client-side JavaScript).
- `OriginProviderInterface` is now independently injectable as `Csrf`'s 5th constructor
  argument, instead of being resolved only via an `instanceof` check against the injected
  `ClientContextProviderInterface`.

### Changed

- `HtmlHelper::input()` now issues tokens via `issueFor()` and transparently emits a third
  hidden input, `_csrf_proof`, whenever a session-bound proof is available. The Plates, Twig,
  and Blade view helpers all delegate to `input()` and inherit this with no template changes.
- `Csrf::validateFor()` gained a trailing optional `$proof` parameter;
  `Csrf::validateCachedFor()` gained trailing optional `$rawToken` and `$proof` parameters (the
  raw token is required to verify a proof on the cache fast path).
  `CsrfCacheWrapper::validateFor()` gained a trailing optional `$proof` parameter.
- Minimum PHP version raised from `>=7.4` to `>=8.2`, required by `CsrfPair`'s class-level
  `readonly` modifier (`final readonly class`) — a PHP 8.2 feature; readonly *properties* alone
  would only require 8.1.
- CI matrix updated to PHP 8.2 / 8.3 / 8.4.

### Fixed

- `Helpers/Plates/CsrfExtension.php`'s `csrf_token()` called `HtmlHelper::token()`, a method
  that did not exist — the function was fatal at call time. `token()` is now implemented.

### Documentation

- README: origin binding vs. the `allowed_origins` whitelist, session-bound proof (config,
  `SessionBindingProviderInterface`, validation order), and token lifecycle guidance (single-use
  behavior, the Back button/BFCache interaction, a refresh-endpoint pattern, and monitoring
  expiration via `getExpiresInFor()`).

### Backward compatibility

- `generate()` / `validate()` / `generateFor()` / `validateFor()` call sites are unaffected: all
  new parameters are trailing and optional, and `generateFor()` never computes a proof (no
  behavioral or performance change for callers not using the new features).
- Existing `withContainer()` configs are unaffected: `origin` defaults to `null` (binding
  disabled) and `require_proof` defaults to `false` (proof verified only when submitted, never
  required).
- **Breaking**: minimum supported PHP version is now 8.2. Consumers on PHP 7.4–8.1 must stay on
  the `1.4.x` line or upgrade their PHP runtime.

### Testing

- 51 tests / 72 assertions (PHPUnit), covering origin binding, session-bound proof (valid/wrong
  proof, tampered token, cross-session, cross-container, `require_proof` on/off, malformed and
  oversized input, key separation), and the `OriginProviderInterface` resolution fallback.
- `phpcs` (project ruleset): clean.
