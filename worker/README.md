# captcha worker

Cloudflare Worker replacing the Rust/axum service in `../src`. Same two routes,
same status codes, same `{"message": ...}` bodies — the sites need no changes.

| Route | Behaviour |
|---|---|
| `GET /health` | `{"message":"Healthy"}` |
| `POST /captcha` | form-urlencoded; verifies a reCAPTCHA Enterprise token, then emails the form via Resend |

`src/app.ts` holds all the logic and takes its dependencies (fetch, email
sender) as arguments, so the suite in `test/` runs without the workerd runtime.
`src/index.ts` only wires up Sentry and the real Resend sender.

## Local development

```sh
pnpm install
cp .dev.vars.example .dev.vars   # fill in real values; never commit this
pnpm dev                         # http://localhost:8787
pnpm test                        # 19 tests
pnpm typecheck
```

## Configuration

`ALLOWED_ORIGINS` lives in `wrangler.jsonc` (not a secret). Everything else is
a secret, set once per environment:

```sh
npx wrangler secret put GOOGLE_ENTERPRISE_API_KEY
npx wrangler secret put GOOGLE_PROJECT_ID
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put SENTRY_DSN                 # optional; empty disables Sentry

# Per site. The `site` field posted by each form, uppercased, is the prefix.
npx wrangler secret put DONALDSON_AFRICA_RECAPTCHA_SITE_KEY
npx wrangler secret put DONALDSON_AFRICA_EMAIL_TO
npx wrangler secret put DONALDSON_AFRICA_EMAIL_FROM
npx wrangler secret put STEAD_AFRICA_RECAPTCHA_SITE_KEY
npx wrangler secret put STEAD_AFRICA_EMAIL_TO
npx wrangler secret put STEAD_AFRICA_EMAIL_FROM
```

Adding a site later means three more secrets and one more entry in
`ALLOWED_ORIGINS` — no code change.

## Deploy

```sh
pnpm run deploy   # note: `pnpm deploy` is a built-in pnpm command, not this script
```

Then attach the custom domain `captcha.stead.africa` to the Worker
(Workers & Pages → captcha → Settings → Domains & Routes), which is the
hostname both sites already post to.

## Differences from the Rust original

- Email goes over the Resend REST API instead of the `resend-rs` crate.
- Sentry is `@sentry/cloudflare`; an unset `SENTRY_DSN` disables it cleanly
  rather than panicking at startup as the Rust version did.
- Email body field order is now stable (insertion order) instead of Rust's
  randomised `HashMap` iteration order.
- Only a lowercase `email` field is format-checked, exactly as before. The
  stead. form posts `Email`, so it is not validated — preserved deliberately;
  fix it in both places together if you want it covered.
