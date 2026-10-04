# Cawala — Web App Deployment & Availability

How to serve the browser app on `cawala.ca` (or your own domain) with no single
point of failure — and how anyone else can deploy it. The goal is that the
canonical operator is never the only path to the app.

## Constraints that drive the design

1. **Stable origin.** Browser identity/ledger state (`cawala.identity.v1`,
   `cawala.state.v1:<nodeId>`, …) and the service-worker scope are
   **origin-scoped**. Changing hostname (a different `github.io` path, a new IPFS
   CID subdomain, a mirror hostname) forces identity export/import. Failover that
   preserves identity must keep `https://cawala.ca`.
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
                    cawala.ca  (apex, stable origin, identity anchor)
                         │
     ┌───────────────────┼──────────────────────────┐
     │                   │                          │
[ CANONICAL ]     [ SAME-ORIGIN FAILOVER ]    [ INDEPENDENT MIRRORS ]
Cloudflare        health-checked second       different origins:
Pages / Workers   origin (VPS nginx/Caddy,    <cid>.ipfs.cawala.ca,
Static Assets     S3+CloudFront) same cert   community domains, IPFS
  _headers        + same headers  ~$0–5/mo    read-only / fresh identity
     │                   │                          │
  full PWA           full PWA                  bootstrap + availability
```

- **Layer 0 — source/artifacts.** `web/dist` is the deployment unit. CI builds a
  deterministic tarball per tag and attests it. This is what makes mirrors
  possible.
- **Layer 1 — canonical origin.** One stable hostname (`cawala.ca`) carrying
  identity and the service worker, on a header-capable managed host.
- **Layer 2 — same-origin failover.** A health-checked second origin that also
  serves `cawala.ca` with a valid cert and the same headers. Removes the *host*
  as a SPOF while keeping the origin.
- **Layer 3 — independent mirrors.** Content-addressed IPFS and community-hosted
  copies on their own domains. Different origins, so read-only bootstrap/demo —
  but they remove any single host or pinner as a SPOF.

**Same-origin redundancy protects identity; different-origin mirrors protect
availability.** You want both.

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
  2. **Identity export/import** (`Settings → Identity`) so users can move to a
     mirror and restore their account.
- **The protocol doesn't depend on the web app.** Nodes are independent; the app
  is a stateless client except for local identity. If the canonical origin
  vanished, the network keeps running and users can load any mirror.

## Containers (Docker) — optional

Docker is **not** needed for the canonical origin and doesn't reduce SPOF by
itself. Where it can help:

- **A reproducible self-hosted failover/mirror origin.** A tiny image that serves
  `web/dist` with a copy of the header policy (e.g. `nginx:alpine` + an
  `nginx.conf`) makes the VPS/failover origin trivial to rebuild and pin by
  digest. The digest gives a verifiable artifact, complementing the attestation.
- **Local preview** of the production build with real headers (`npm run build`
  then serve `dist/`, not `vite preview`).

It does **not** help with: origin-scoped identity, custom-header support beyond
what your web server already does, or the relay architecture. Keep it to the
failover/mirror role; the managed primary (Cloudflare) remains simpler.

## Repo artifacts

- `web/public/_headers` — Cloudflare Pages CSP/HSTS/cache policy.
- `web/netlify.toml` — Netlify build + `[[headers]]`.
- `web/vercel.json` — Vercel headers.
- `web/public/sw.js` + `web/scripts/stamp-sw.mjs` — per-deploy SW versioning.
- `.github/workflows/release.yml` — node binaries, packaging assets, and the
  checksummed + attested web artifact.
- `.github/workflows/ipfs.yml` — optional IPFS publish/pin on `v*` tags.
- `MIRRORS.md` — mirror list format/signing.
