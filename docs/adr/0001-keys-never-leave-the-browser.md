# Keys never leave the browser

The tool is a Blazor WebAssembly app. Any Key a user pastes (symmetric Secret or RSA key pair) exists only in browser memory: no token or key material is ever sent to a server, and nothing is persisted (no localStorage, no recent-history).

We chose WASM over interactive-server rendering because a JWT tool that transmits users' secrets to its own backend would be unusable as a public tool, and server-side interactivity buys nothing for a pure client-side transform. Consequence: the app deploys as static files and every crypto operation must be possible in-browser.

## Addendum — the boundary this guarantee draws (2026-09-20)

"Never leaves the browser" is a **network** guarantee: no key material is transmitted to any server, by this app or its dependencies. It is not an **isolation** guarantee. Key material lives in the memory of the web page, and any script running in that page — including browser extensions, which the user has granted page access — can read it. For highly sensitive keys, use a dedicated private-browsing window with extensions disabled, or a native tool. The app states this boundary in its key-entry hints (see the RS256 and verify hints).
