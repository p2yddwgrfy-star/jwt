# Keys never leave the browser

The tool is a Blazor WebAssembly app. Any Key a user pastes (symmetric Secret or RSA key pair) exists only in browser memory: no token or key material is ever sent to a server, and nothing is persisted (no localStorage, no recent-history).

We chose WASM over interactive-server rendering because a JWT tool that transmits users' secrets to its own backend would be unusable as a public tool, and server-side interactivity buys nothing for a pure client-side transform. Consequence: the app deploys as static files and every crypto operation must be possible in-browser.
