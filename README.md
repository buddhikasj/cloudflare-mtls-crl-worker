# CRL-worker

A Cloudflare Worker that forwards requests while extracting CRL Distribution Point URLs from the presented mTLS client certificate, checks revocation via cached CRLs in Workers KV, and applies simple pass-through logic based on the request host.

## Overview

- **Entry**: `src/index.js`
- **KV Binding**: `CRL_NAMESPACE` (configured in `wrangler.toml`)
- **Host gating**: Only processes requests when `Host` header equals `CONFIG.host`; otherwise passes through.
- **Outcome**:
  - Adds `X-Client-Cert-CRL-URLs` header when URLs are found.
  - Returns `403` if the client certificate is revoked.
  - Returns `500` if no CRLs can be loaded.
  - Otherwise forwards the request upstream.

## Special Behaviors
- **Force CRL refresh header**: `FORCE_CRL_REFRESH_HEADER`
  - When present (any value), the Worker forces a refresh of the CRL for each distribution point before evaluation.
  - Header name should match the code constant if you enable this path in `src/index.js`.
- **Client cert header**: `cf-client-cert-der-base64` must be present (Cloudflare provides it when mTLS is enabled and verification succeeds).

## Deployment
- Ensure Wrangler is configured for your Cloudflare account and the KV namespace is created/bound as in `wrangler.toml`.

```bash
# from worker/crl_worker/
npm install
npm run deploy
# or
npx wrangler deploy
```

## Create the KV namespace
- Create the namespace and note the returned ID:

```bash
wrangler kv namespace create CRL_NAMESPACE
```

- Bind it in `wrangler.toml` using the returned `id`:

```toml
[[kv_namespaces]]
binding = "CRL_NAMESPACE"
id = "<YOUR_KV_NAMESPACE_ID>"
```

## Configuration
- Update `CONFIG.host` in `src/index.js` to the expected host for which the Worker should actively process requests.


## Add routes in `wrangler.toml`
- Add routes so traffic for your hostname is handled by this Worker. Replace with your own `zone_id` and host.

```toml
routes = [
  { pattern = "<URI_PATH>", zone_id = "<YOUR_ZONE_ID>" }
]
```

- Ports are not part of route patterns; route by hostname/path only.


## Repo/folder name note
- In your repo this folder may be named `crl-worker`. Adjust paths accordingly when running commands (e.g., run from `crl-worker/`).

## Headers
- **Input**: `cf-client-cert-der-base64`
- **Optional**: `FORCE_CRL_REFRESH_HEADER` (enable in code if desired)
- **Output**: `X-Client-Cert-CRL-URLs` (comma-separated list)
