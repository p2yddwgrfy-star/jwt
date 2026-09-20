# 0002 — RS256 in the browser goes through Web Crypto

Date: 2026-09-20

Status: Accepted

## Context

.NET's RSA implementation is unavailable on browser WebAssembly: `RSA.Create()` throws
`PlatformNotSupportedException` in the browser profile, on every .NET version to date
(cryptography APIs on Blazor WebAssembly are a documented platform gap, not a bug).
Until now this was invisible to the test suites: the unit tests run on the desktop
runtime, where BCL RSA works, so RS256 Verify (and Encode) passed everything while being
broken in the shipped app — every RS256 verify crashed the Blazor renderer. The Playwright
E2E suite (ADR-0001's test expansion) caught it on its first RS256 case.

Options considered:

1. **Hand-rolled RSA in managed code** — parse SPKI/PKCS#8 DER, run modexp with
   `BigInteger`, compare PKCS#1 v1.5 padding. Fully synchronous, one code path everywhere,
   but it means shipping self-implemented signature verification, where the historical
   forgery bugs (e.g. Bleichenbacher '06) live in exactly the leniencies a first
   implementation gets wrong. Rejected: the project's posture is to use audited platform
   crypto, not to become a crypto library.
2. **Web Crypto via JS interop** — delegate the RSA operation to `crypto.subtle`
   (`RSASSA-PKCS1-v1_5`), which every supported browser provides. Async, and Blazor-specific
   plumbing is required, but the verification math is the browser's audited implementation,
   and key material still never leaves the browser (upholds ADR-0001). Accepted.

## Decision

- `TokenVerifier` gains an injectable RSA verifier: `VerifyAsync(token, algorithm, key,
  RsaSignatureVerifier?)`. All strict pre-checks (three-part form, header alg cross-check,
  alg:none rejection, base64url decoding) stay in `TokenVerifier` — the delegate only
  decides signatures. The default delegate is BCL RSA, so the library stays platform-neutral
  and the existing sync `Verify` is unchanged for every non-browser caller.
- The app supplies a Web Crypto-backed verifier: C# interop (`RsaWebCrypto`) plus a small
  `js/rsa.js` that imports the PEM as SPKI (public) or PKCS#8 (private) and calls
  `crypto.subtle.verify`. A JS failure maps to `CryptographicException`, so the library's
  existing friendly "key could not be read" verdict handles bad PEMs unchanged.
- The UI's `Reverify` becomes async with a request-sequence guard, so fast typing cannot
  let a stale Web Crypto result overwrite a newer verdict.

## Consequences

- RS256 Verify works in the browser, on audited platform crypto, with keys confined to
  the browser.
- `TokenEncoder`'s RS256 signing still uses BCL RSA and remains broken in the browser
  (the same `PlatformNotSupportedException`); it needs the same delegation for signing.
  Tracked as its own issue — Encode signing was out of scope for the test ticket that
  surfaced this.
- Library consumers on full .NET see no API change: `Verify` keeps its signature and
  semantics, and the delegate is optional.
