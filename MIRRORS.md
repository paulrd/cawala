# Cawala Web App — Mirrors

A place for the community to advertise independent copies of the web app, and
the format for a machine-readable list served at
`https://cawala.ca/.well-known/mirrors.json`.

> **Different origin = separate identity.** A mirror on `alice.example` (or
> `<cid>.ipfs.cawala.ca`) is a distinct browser origin. It is great for
> availability and bootstrapping, but it does **not** carry a user's existing
> identity/ledger state. Users move by exporting their identity from the
> original origin and importing it on the mirror (`Settings → Identity`).

## Why mirrors

The client is a static, open-source, MIT-licensed bundle. Content-addressed
(IPFS) and domain-hosted mirrors mean the canonical operator is never the only
path to the app. The protocol does not depend on the web host at all.

## Machine-readable list

Serve at `/.well-known/mirrors.json` with `Cache-Control: no-cache` (the
`_headers` rule already covers `/.well-known/*`). Sign it and publish the public
key out-of-band. Suggested schema:

```json
{
  "version": 1,
  "origin": "https://cawala.ca",
  "sequence": 1,
  "issued": "2026-10-04T00:00:00Z",
  "expires": "2027-01-04T00:00:00Z",
  "prev": null,
  "mirrors": [
    {
      "url": "https://cawala.ca/",
      "kind": "canonical",
      "operator": "cawala",
      "readonly": false,
      "pubkey": null
    },
    {
      "url": "https://<cid>.ipfs.cawala.ca/",
      "kind": "dnslink-ipfs",
      "operator": "cawala",
      "readonly": true,
      "pubkey": null
    },
    {
      "url": "https://mirror.example/cawala/",
      "kind": "static",
      "operator": "Example operator",
      "readonly": true,
      "pubkey": "RWQ...<minisign public key or operator key>"
    }
  ]
}
```

- `sequence` / `expires` / `prev` let consumers reject rollbacks and stale
  lists.
- `kind`: `canonical`, `dnslink-ipfs`, `static`, `ipns`, …
- `readonly`: a mirror that only serves the app (no shared identity).

### Signing

Simplest (minisign/signify, tiny and Ed25519):

```sh
minisign -G -p cawala.pub -s cawala.key          # once, offline
minisign -Sm mirrors.json -s cawala.key          # -> mirrors.json.minisig
minisign -Vm mirrors.json -p cawala.pub
```

Or keyless in CI, matching the release attestations (Sigstore):

```sh
cosign sign-blob --yes mirrors.json --bundle mirrors.json.sigstore.json
cosign verify-blob mirrors.json --bundle mirrors.json.sigstore.json \
  --certificate-identity-regexp '^https://github.com/paulrd/cawala/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Publish the public key / expected workflow identity somewhere separate from the
list (repo `SECURITY.md`, a DNS TXT record, or the releases page).

## Running a mirror

1. Fetch a released artifact and verify it (see `DEPLOYMENT.md`):
   `gh attestation verify cawala-web-<tag>.tar.gz --repo paulrd/cawala`,
   then `sha256sum -c`.
2. Serve the extracted `site/` on any static host, with the header policy for
   your host (`_headers`, `netlify.toml`, `vercel.json`, nginx, or Caddy —
   recipes in `DEPLOYMENT.md`).
3. Optionally pin the IPFS CID (any provider, or your own Kubo) to add a
   content-addressed mirror.
4. Add yourself to the list by opening a PR (canonical/`readonly` mirrors) or
   ask the canonical operator to include your entry, then sign the updated list.

## Mirror status

_This list is a template. Populate it once mirrors exist._

| URL | Kind | Operator | Read-only | Notes |
| --- | --- | --- | --- | --- |
| https://cawala.ca/ | canonical | cawala | no | managed host |
| https://`<cid>`.ipfs.cawala.ca/ | dnslink-ipfs | cawala | yes | update DNSLink per release |
| _add yours_ | static | — | yes | different origin / separate identity |
