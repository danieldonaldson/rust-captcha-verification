# captcha

reCAPTCHA verification and contact-form email for `stead.africa` and
`donaldson.africa`, running as a Cloudflare Worker at `captcha.stead.africa`.

The service lives in [`worker/`](worker/) — see its README for local
development, configuration and deploys.

## History

This was a Rust/axum service deployed on a VPS via Dokploy. On 2026-08-25 it
was rewritten as a TypeScript Worker and the sites moved to Cloudflare Workers
static assets. The Rust source is gone from the working tree but remains in
git history at `d94a2ac` if you ever need to refer back to it.
