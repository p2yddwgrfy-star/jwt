# JWT Tool

A browser-side tool for decoding, verifying, and encoding JSON Web Tokens. Keys are user-supplied and used entirely inside the browser — never sent to any server, never persisted; page-scoped script (such as browser extensions) can still read in-memory key material (ADR-0001).

## Language

**Decode**:
Parsing a Token's header and payload into readable JSON for display, with human-readable time claims. Requires no Key.
_Avoid_: inspect, parse (as the user-facing verb)

**Verify**:
Checking a Token's Signature against a user-supplied Key and reporting valid or invalid. A separate operation from Decode, which never judges validity. In the browser, RS256 verification goes through an injectable RSA-verifier delegate (`RsaSignatureVerifier`) backed by the browser's Web Crypto; on full .NET the BCL is the default (ADR-0002). The strict pre-checks — three-part rule, header alg cross-check, `alg: none` rejection — always stay in the library; the delegate only decides signatures.
_Avoid_: validate, check

**Encode**:
Constructing a new Token from editable header and payload JSON and signing it with a Key. The counterpart of Decode. RS256 signing mirrors Verify: an injectable signer delegate (`RsaSignatureSigner`) carries the browser's Web Crypto path; the BCL signs on full .NET.
_Avoid_: sign, generate, create

**Key**:
The keying material the user supplies for Verify or Encode — a symmetric Secret (HS family) or an RSA key pair. Used without being sent anywhere and never persisted; it lives in page memory, where browser extensions and other page-scoped script can read it (see the intro and ADR-0001's addendum).
_Avoid_: password, credential

**Token**:
The compact three-part string — base64url Header, Payload, Signature joined by dots — that a user pastes or encodes.
_Avoid_: JWT string, credential

**Signature**:
The third part of a Token: the HMAC or RSA value computed over Header.Payload with a Key. Its correctness is what Verify judges.
_Avoid_: hash, checksum

**Claim**:
A named value inside the Token's payload (e.g. `sub`, `exp`, `iat`). Time claims are shown as human-readable dates with expired/not-yet-valid badges.
_Avoid_: field, property

**Warning**:
A non-fatal annotation on a decoded Token — a malformed part, unsigned `alg: none`, missing or expired time claim. Decode surfaces Warnings; they never block display.
_Avoid_: error (reserved for unparseable input)

**Stale response**:
The result of an async operation that started before the user's latest input and finished after it. The UI never lets a stale response win: both async flows (RS256 Verify, RS256 Encode) take a request id from `RequestSequenceGuard` before awaiting and only apply their result if it is still the latest.
_Avoid_: race, out-of-order result
