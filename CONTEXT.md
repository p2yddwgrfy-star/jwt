# JWT Tool

A browser-side tool for decoding, verifying, and encoding JSON Web Tokens. Keys are user-supplied and never leave the browser; nothing is persisted.

## Language

**Decode**:
Parsing a Token's header and payload into readable JSON for display, with human-readable time claims. Requires no Key.
_Avoid_: inspect, parse (as the user-facing verb)

**Verify**:
Checking a Token's Signature against a user-supplied Key and reporting valid or invalid. A separate operation from Decode, which never judges validity.
_Avoid_: validate, check

**Encode**:
Constructing a new Token from editable header and payload JSON and signing it with a Key. The counterpart of Decode.
_Avoid_: sign, generate, create

**Key**:
The keying material the user supplies for Verify or Encode — a symmetric Secret (HS family) or an RSA key pair. Never leaves the browser, never persisted.
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
