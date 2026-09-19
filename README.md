# JWT Tool

A browser-side tool for decoding, verifying, and encoding JSON Web Tokens — in the spirit of [jwt.io](https://jwt.io), built with Blazor WebAssembly.

**Live site:** https://peterleing.github.io/jwt/

All operations run entirely in your browser. Keys and tokens are never sent to any server, and nothing is persisted — see [ADR-0001](docs/adr/0001-keys-never-leave-the-browser.md). Domain vocabulary lives in [CONTEXT.md](CONTEXT.md).

## Features

- **Decode** — paste a token to see its header and payload as pretty-printed JSON, with time claims (`exp`, `iat`, `nbf`) shown as human-readable dates and expired / not-yet-valid badges. Decode is lenient: unusual tokens (unsigned `alg: none`, malformed parts) render with warnings instead of errors.
- **Verify** — paste a key (text secret for HS256/HS384/HS512, PEM key pair for RS256), pick the algorithm, and get a strict valid/invalid verdict with the reason. The header's `alg` is cross-checked; unsigned tokens are refused.
- **Encode** — edit header and payload JSON, supply a key, and get a signed token live as you type. From the Decode view, "Tweak & re-encode" carries the decoded JSON straight into the editor.
- Color-coded token parts (header / payload / signature), one-click copy, dark theme.

## Run locally

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (`dotnet --list-sdks` should show 10.0.x). **No IIS or other web server is required** — the app ships its own dev server, and the production build is pure static files.

### Option 1: dev server (quickest)

From the repository root:

```bash
dotnet run --project src/JwtTool.App --urls http://127.0.0.1:5116 -- --pathbase=/jwt
```

Then open **http://127.0.0.1:5116/jwt/**.

(The `--pathbase=/jwt` flag mirrors the `/jwt/` base href used by GitHub Pages. If you change the base href in `src/JwtTool.App/wwwroot/index.html` back to `/`, you can drop the flag.)

### Option 2: serve the published static files

The Release build is a plain static site — any static file server works:

```bash
dotnet publish src/JwtTool.App -c Release -o publish
```

Serve `publish/wwwroot` with your favorite static file server, e.g.:

```bash
dotnet tool install -g dotnet-serve
dotnet-serve -d publish/wwwroot -p 8080
```

Make sure the server sends `.wasm` files as `application/wasm` (dotnet-serve does). Alternatively, drop `publish/wwwroot` onto any static host — that is exactly how the GitHub Pages deployment works.

## Development

### Build and test

```bash
dotnet build JwtTool.slnx
dotnet test tests/JwtTool.TokenOperations.Tests
dotnet test tests/JwtTool.App.E2E   # first run: pwsh tests/JwtTool.App.E2E/bin/Debug/net10.0/playwright.ps1 install chromium
```

The solution has four projects:

| Project | Purpose |
|---|---|
| `src/JwtTool.App` | Blazor WebAssembly UI (thin binding over the library) |
| `src/JwtTool.TokenOperations` | The Token Operations seam: Decode, Verify, Encode |
| `tests/JwtTool.TokenOperations.Tests` | xUnit unit tests at the Token Operations seam |
| `tests/JwtTool.App.E2E` | Playwright end-to-end tests: spawn the real app and drive it in Chromium |

JWT logic is covered at the library seam (round-trip, warning catalog, strict-verify tests); the E2E suite covers the UI flows themselves — decode, verify, encode, tab-switch state, and the tweak-and-re-encode path — in the Pages-shaped `/jwt/` layout.

### Deployment

`push` to `main` runs [.github/workflows/deploy-pages.yml](.github/workflows/deploy-pages.yml): unit tests, publishes the static site, and deploys to GitHub Pages at the `/jwt/` subpath — and [.github/workflows/e2e.yml](.github/workflows/e2e.yml) runs the browser end-to-end suite. No manual steps.

Known limitation: GitHub Pages does not let you set HTTP response headers, so a strict Content-Security-Policy cannot be enforced there. The app's design already minimizes what a CSP would guard (no backend, no data leaves the browser — see ADR-0001). A self-hosted deployment can add a strict CSP.

### Project docs

- [CONTEXT.md](CONTEXT.md) — the project glossary (Decode, Verify, Encode, Key, Token, Signature, Claim, Warning)
- [docs/adr/](docs/adr/) — architecture decision records
- [docs/agents/](docs/agents/) — agent configuration (issue tracker, triage labels, domain docs)
