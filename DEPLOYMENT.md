# Cawala — Web App Deployment & Availability

How to serve the browser app on `cawala.ca` (or your own domain) with no single
point of failure — and how anyone else can deploy it. The goal is that the
canonical operator is never the only path to the app.

## Constraints that drive the design

1. **State is a best-effort cache; identity is portable.** Since the
   portable-client refactor (R1) the browser holds no authoritative
   account/ledger/admin state: `cawala.state.v1:<nodeId>` and
   `cawala.ledger.v1:<nodeId>` are re-derivable caches, so a **fresh origin
   boots with empty local state** and revalidates balance, height, topology and
   the admin views from the node. What stays local, and does not follow the user
   to another host, is the per-origin service-worker/cache scope, the TOFU
   leaf-key *trust decision*, the quarantined ledger backup, and the in-flight
   value journal. Identity is mnemonic-derived and portable (R3): the same
   BIP-39 mnemonic restores the user's ETH account *and* the transport NodeId on
   any host, so a new hostname does **not** force an identity export/import —
   the user re-joins that leaf with a fresh invite (queued for operator
   approval; the node keeps the child, its address/slot and its ledger). To move
   an install byte-for-byte instead, export/import the encrypted identity
   bundle, which also carries the local join/ledger state. Same-origin failover
   (Layer 2) still preserves the SW and cache.
2. **Custom response headers.** CSP, HSTS, and cache-control are required.
   GitHub Pages cannot set response headers; the host must honor `_headers`,
   `netlify.toml` `[[headers]]`, or `vercel.json`.
3. **Not a demo.** GitHub Pages' ToS forbids commercial/financial use; Vercel
   Hobby is non-commercial-only. Production needs a host that permits it.
4. **Anyone can build it.** The source is MIT-licensed and the build is
   documented and reproducible; a released web artifact is checksummed and
   provenance-attested so third parties can verify before serving.

## Recommended topology

```
                    cawala.ca  (apex; stable origin for SW + local cache)
                         │
     ┌───────────────────┼──────────────────────────┐
     │                   │                          │
[ CANONICAL ]     [ SAME-ORIGIN FAILOVER ]    [ INDEPENDENT MIRRORS ]
Cloudflare        health-checked second       different origins:
Pages / Workers   origin (VPS nginx/Caddy,    <cid>.ipfs.cawala.ca,
Static Assets     S3+CloudFront) same cert   community domains, IPFS
  _headers        + same headers  ~$0–5/mo    identity-portable
     │                   │                          │
  full PWA           full PWA                  bootstrap + availability
```

- **Layer 0 — source/artifacts.** `web/dist` is the served deployment unit; the
  single-file `web/dist-single/index.html` is also produced for offline/email/zip
  distribution. CI builds a deterministic tarball per tag and attests it. This is
  what makes mirrors possible.
- **Layer 1 — canonical origin.** One stable hostname (`cawala.ca`) carrying the
  service worker and local cache, on a header-capable managed host. (Identity is
  portable by mnemonic and account/ledger state is re-derivable from the node,
  so the cache is only a convenience — but the local leaf-key trust decisions
  are origin-scoped, so returning here preserves them while a new mirror
  re-establishes them.)
- **Layer 2 — same-origin failover.** A health-checked second origin that also
  serves `cawala.ca` with a valid cert and the same headers. Removes the *host*
  as a SPOF while keeping the origin.
- **Layer 3 — independent mirrors.** Content-addressed IPFS and community-hosted
  copies on their own domains. Different origins, but identity is portable: a
  user restores the same account and NodeId by entering their mnemonic, and the
  fresh origin rebuilds account/ledger/admin state from the node. They remove
  any single host or pinner as a SPOF.

**Same-origin redundancy preserves the service worker and local cache;
different-origin mirrors protect availability. Identity rides the mnemonic, not
the origin — and a cache miss on a new origin is now a cache miss, not data
loss.** You want both.

## Self-host in 5 minutes

### Option A — build from source (needs Node 24, Rust + `wasm32-unknown-unknown`, wasm-bindgen 0.2.122, a C compiler)

```sh
git clone https://github.com/paulrd/cawala && cd cawala
git checkout v0.1.0                # or main

rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.122

cd web
npm ci
npm run build                      # -> web/dist/ (includes _headers, stamped sw.js)
```

### Option B — use the released, verified artifact (no Rust toolchain)

```sh
tag=v0.1.0
base="https://github.com/paulrd/cawala/releases/download/$tag"
curl -fsSLO "$base/cawala-web-$tag.tar.gz"
curl -fsSLO "$base/cawala-web-$tag.tar.gz.sha256"
sha256sum -c "cawala-web-$tag.tar.gz.sha256"        # verify the tarball

# Verify build provenance (requires a recent gh CLI):
gh attestation verify "cawala-web-$tag.tar.gz" \
  --repo paulrd/cawala \
  --signer-workflow paulrd/cawala/.github/workflows/release.yml

mkdir site && tar -xzf "cawala-web-$tag.tar.gz" -C site   # extracts the site root
```

Then serve `site/` (or `web/dist/`) on any static host with the headers below.
Never re-pack the tarball — re-archiving changes the bytes and invalidates the
digest.

## Single-file distribution (`dist-single/index.html`)

`npm run build:singlefile` produces **one self-contained file**,
`web/dist-single/index.html`, with all JS/CSS inlined and the wasm embedded as
base64 and initialized from bytes. It is the distributable for `file://`, zip,
email, and header-less hosts — anywhere the multi-asset `dist/` is inconvenient.

- **Do NOT serve `dist-single` from the canonical origin.** The served deployment
  stays the multi-asset `dist/`. A host that sends the standard CSP header
  (`script-src 'self' 'wasm-unsafe-eval'` — no `'unsafe-inline'`) would **blank
  the page**: the single file carries its own `<meta http-equiv="Content-Security-Policy">`
  that permits the inline bundle, and when both a header and a meta CSP are
  present the browser enforces their **intersection**, so the inline `<script>`
  is blocked.
- Use `dist-single` only where no conflicting header CSP is applied, or with a
  relaxed policy that includes `script-src 'unsafe-inline'` (and
  `'wasm-unsafe-eval'`). Publish it as a release asset / zip, not as the main site.
- **On `file://`** passkeys and service workers are unavailable (no secure
  origin / scope), so the app runs in degraded mode: **mnemonic unlock only**,
  no passkey panel, no SW, best-effort storage. Everything else (app logic, wasm,
  `crypto.subtle`) works.

## Per-host header recipes

Each host has exactly one source of truth: `web/public/_headers` for Cloudflare,
`web/netlify.toml` for Netlify, `web/vercel.json` for Vercel, and a server config
for nginx/Caddy. All set the same CSP/HSTS/cache policy.

### Cloudflare Pages / Workers Static Assets (recommended primary)

Uses `web/public/_headers` verbatim (copied to `dist/_headers`). Cloudflare
**merges** all matching rules, so specific rules and the `/*` catch-all combine.
Caveat: `_headers` does not apply to Pages Functions/SSR responses.

### Netlify

Uses `web/netlify.toml` (`[[headers]]`). Netlify is **first-match**, so the config
lists specific paths before the catch-all and the build removes `dist/_headers`
so it can't shadow these rules. Set the site "Base directory" to `web`.

### Vercel

Uses `web/vercel.json`. Set the project root to `web`. Hobby is
non-commercial-only; use Pro for a financial app.

### nginx (self-hosted failover)

`add_header` is only inherited when the nested level defines **no** `add_header`
of its own, so repeat the security headers via an `include` snippet (portable),
or use nginx ≥ 1.29.3's `add_header_inherit merge`.

```nginx
# /etc/nginx/snippets/cawala-security-headers.conf
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' blob: https://dns.iroh.link https://*.relay.n0.iroh.link wss://*.relay.n0.iroh.link; worker-src 'self' blob:; manifest-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
```

```nginx
server {
    listen 443 ssl;
    server_name cawala.ca;
    root /srv/cawala/site;

    location /assets/ {
        include /etc/nginx/snippets/cawala-security-headers.conf;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
    }
    location = /index.html { include /etc/nginx/snippets/cawala-security-headers.conf; add_header Cache-Control "no-cache" always; }
    location = /sw.js      { include /etc/nginx/snippets/cawala-security-headers.conf; add_header Cache-Control "no-cache" always; }

    location / {
        include /etc/nginx/snippets/cawala-security-headers.conf;
        add_header Cache-Control "no-cache" always;
        try_files $uri /index.html;
    }
}
```

### Caddy v2 (self-hosted failover)

Caddy does automatic HTTPS but **not** HSTS — set it explicitly.

```caddy
cawala.ca {
    root * /srv/cawala/site
    encode zstd gzip

    header {
        Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' blob: https://dns.iroh.link https://*.relay.n0.iroh.link wss://*.relay.n0.iroh.link; worker-src 'self' blob:; manifest-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        X-Content-Type-Options nosniff
        Referrer-Policy strict-origin-when-cross-origin
    }
    header /assets/* Cache-Control "public, max-age=31536000, immutable"

    @nocache path / /index.html /sw.js /manifest.webmanifest
    header @nocache Cache-Control "no-cache"

    try_files {path} /index.html
    file_server
}
```

### GitHub Pages

Cannot set response headers at all. A `<meta http-equiv>` is not a substitute
(it cannot set HSTS, `X-Frame-Options`, or `Cache-Control`, and covers only part
of CSP). To use it at all, put a header-capable proxy in front (Cloudflare
Transform Rule / Worker), or migrate to a host above. Also ToS-restricted for
commercial/financial use.

## Verifying a release artifact

Every `v*` release carries:

- `cawala-web-<tag>.tar.gz` — deterministic tarball of the built site.
- `cawala-web-<tag>.tar.gz.sha256` — checksum of the tarball.
- `cawala-web-<tag>.SHA256SUMS` — per-file checksums inside the site.

The tarball is provenance-attested with `actions/attest@v4` (SLSA build
provenance, keyless via Sigstore). Verify before serving:

```sh
gh attestation verify cawala-web-<tag>.tar.gz \
  --repo paulrd/cawala \
  --signer-workflow paulrd/cawala/.github/workflows/release.yml
sha256sum -c cawala-web-<tag>.tar.gz.sha256
```

`--signer-workflow` matters: `--repo` alone accepts an attestation from any
workflow in the repo.

## IPFS mirror + pin federation

The `.github/workflows/ipfs.yml` job (on `v*` tags) computes a **deterministic
CIDv1** (`unixfs-v1-2025`), exports the CAR, and pins it to the configured
provider(s). It is skipped (green) unless a provider secret exists.

Publishing a CID is useless unless someone pins it — and that is exactly how you
avoid depending on the canonical operator. **Anyone can pin the same CID**:

```sh
ipfs init
ipfs config profile apply unixfs-v1-2025
# serve/pin the released artifact; the CID matches the CI-produced one:
ipfs add -Qr ./site
# or pin the published CID via a pinning service's UI/API (Filebase, Pinata, Storacha)
```

Serve it under your domain with a **subdomain gateway** (`<cid>.ipfs.cawala.ca`),
never a shared path gateway, so each root gets its own origin (service-worker
isolation). See `MIRRORS.md` for the mirror list and signing.

## Mirror discovery and tamper-evidence

Publish the mirror list on the canonical origin so it inherits HSTS/CSP:

```
https://cawala.ca/.well-known/mirrors.json
https://cawala.ca/.well-known/mirrors.json.minisig   (or .sigstore.json)
```

Sign it (minisign is simplest; `cosign sign-blob` keyless matches the release
attestations) and publish the public key **out-of-band** (repo `SECURITY.md`,
DNS TXT, releases page). Include `sequence`/`expires`/`prev` so consumers can
reject rollbacks. Format and template: `MIRRORS.md`.

## You are not a single point of failure

- **Code availability** is handled by open source + reproducible/attested
  artifacts + IPFS mirrors + this self-host guide. Anyone can serve the app; no
  permission needed.
- **Identity anchor** (`cawala.ca`) is a governance point by nature. Same-origin
  redundancy (Layer 2) needs shared control of the domain/DNS across ≥2
  operators. If you can't arrange that, the escape hatch is:
  1. **Different-origin mirrors** for availability, and
  2. **Mnemonic restore** — the user's ETH identity *and* transport NodeId are
     derived from their BIP-39 mnemonic, so entering it on any mirror restores
     the account (the old "different origin = separate identity" limitation is
     gone). Account/ledger/admin state is re-derived from the node; only the
     local TOFU leaf-key decisions and the quarantined ledger backup stay on the
     old origin (trust is re-confirmed after re-joining, or carried over with an
     identity-bundle import). Derived secrets are persisted per-device; the
     mnemonic is never stored.
- **The protocol doesn't depend on the web app.** Nodes are independent; the app
  is a stateless client except for local authoritative state (identity, TOFU
  pins, the quarantine backup, and the in-flight value journal). If the
  canonical origin vanished, the network keeps running and users can load any
  mirror.

## Containers (Docker) — optional

Docker is **not** needed for the canonical origin and doesn't reduce SPOF by
itself. Where it can help:

- **A reproducible self-hosted failover/mirror origin.** A tiny image that serves
  `web/dist` with a copy of the header policy (e.g. `nginx:alpine` + an
  `nginx.conf`) makes the VPS/failover origin trivial to rebuild and pin by
  digest. The digest gives a verifiable artifact, complementing the attestation.
- **Local preview** of the production build with real headers (`npm run build`
  then serve `dist/`, not `vite preview`).

It does **not** help with: per-origin service-worker/cache scope (a cache miss
on a new origin is harmless now — the node re-supplies state), custom-header
support beyond what your web server already does, or the relay architecture. Keep
it to the failover/mirror role; the managed primary (Cloudflare) remains simpler.

## Repo artifacts

- `web/public/_headers` — Cloudflare Pages CSP/HSTS/cache policy.
- `web/netlify.toml` — Netlify build + `[[headers]]`.
- `web/vercel.json` — Vercel headers.
- `web/public/sw.js` + `web/scripts/stamp-sw.mjs` — per-deploy SW versioning.
- `web/vite.config.singlefile.js` + `web/scripts/check-singlefile.mjs` — the
  self-contained `dist-single/index.html` build and its self-containment check.
- `.github/workflows/release.yml` — node binaries, packaging assets, and the
  checksummed + attested web artifact.
- `.github/workflows/ipfs.yml` — optional IPFS publish/pin on `v*` tags.
- `MIRRORS.md` — mirror list format/signing.
