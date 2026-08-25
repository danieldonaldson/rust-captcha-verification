import { AppError } from './errors';

/**
 * TypeScript port of the axum service in ../src/main.rs.
 *
 * Behaviour is deliberately identical, including status codes and the exact
 * `{ "message": ... }` response bodies the two websites already parse.
 */

export const EMAIL_REGEX =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

export const SITE_NAME_REGEX = /^[a-zA-Z0-9_-]+$/;

/** Matches the 1 MiB `RequestBodyLimitLayer` on the axum router. */
export const MAX_BODY_BYTES = 1024 * 1024;

const RECAPTCHA_TIMEOUT_MS = 10_000;

export interface Env {
  GOOGLE_ENTERPRISE_API_KEY: string;
  GOOGLE_PROJECT_ID: string;
  RESEND_API_KEY: string;
  ALLOWED_ORIGINS: string;
  SENTRY_DSN?: string;
  /** Overridable so tests can point at a stub instead of Google. */
  RECAPTCHA_API_BASE?: string;
  /** Per-site config: {SITE}_RECAPTCHA_SITE_KEY / _EMAIL_TO / _EMAIL_FROM */
  [key: string]: string | undefined;
}

export interface EmailSender {
  send(
    apiKey: string,
    from: string,
    to: string,
    subject: string,
    body: string,
  ): Promise<void>;
}

export interface Deps {
  emailSender: EmailSender;
  fetch: typeof fetch;
  /** Sentry capture in production; a spy in tests. */
  onError?: (error: unknown) => void;
}

/** Sends via the Resend HTTP API — replaces the `resend-rs` crate. */
export class ResendEmailSender implements EmailSender {
  constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  async send(
    apiKey: string,
    from: string,
    to: string,
    subject: string,
    body: string,
  ): Promise<void> {
    let response: Response;
    try {
      response = await this.fetchImpl('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ from, to: [to], subject, text: body }),
      });
    } catch (error) {
      throw AppError.resend(`Failed to send email: ${String(error)}`);
    }

    if (!response.ok) {
      const detail = await response.text().catch(() => '<unreadable>');
      throw AppError.resend(
        `Failed to send email: ${response.status} ${detail}`,
      );
    }
  }
}

function json(
  body: unknown,
  status: number,
  headers: Record<string, string>,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function message(
  text: string,
  status: number,
  headers: Record<string, string>,
): Response {
  return json({ message: text }, status, headers);
}

/**
 * Equivalent of `CorsLayer::new().allow_origin(origins).allow_credentials(true)`:
 * the origin is echoed back only when it is on the allow-list.
 */
export function corsHeaders(
  request: Request,
  env: Env,
): Record<string, string> {
  const headers: Record<string, string> = { Vary: 'Origin' };
  const origin = request.headers.get('Origin');
  if (!origin) return headers;

  const allowed = (env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

  if (allowed.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Credentials'] = 'true';
  }
  return headers;
}

export async function handle(
  request: Request,
  env: Env,
  deps: Deps,
): Promise<Response> {
  const url = new URL(request.url);
  const cors = corsHeaders(request, env);

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        ...cors,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'content-type, authorization, accept',
        'Access-Control-Max-Age': '86400',
      },
    });
  }

  if (url.pathname === '/health') {
    if (request.method !== 'GET') {
      return message('Method not allowed', 405, cors);
    }
    return message('Healthy', 200, cors);
  }

  if (url.pathname === '/captcha') {
    if (request.method !== 'POST') {
      return message('Method not allowed', 405, cors);
    }
    return handleCaptcha(request, env, deps, cors);
  }

  return message('Not found', 404, cors);
}

async function handleCaptcha(
  request: Request,
  env: Env,
  deps: Deps,
  cors: Record<string, string>,
): Promise<Response> {
  const declaredLength = Number(request.headers.get('Content-Length') ?? '0');
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    return message('Payload too large', 413, cors);
  }

  let body: string;
  try {
    body = await request.text();
  } catch (error) {
    deps.onError?.(error);
    return message('Invalid form data', 400, cors);
  }

  if (new TextEncoder().encode(body).length > MAX_BODY_BYTES) {
    return message('Payload too large', 413, cors);
  }

  const form = new URLSearchParams(body);
  const token = form.get('g-recaptcha-response');
  const site = form.get('site');

  // axum's `Form<CaptchaForm>` rejects a body missing either named field.
  if (token === null || site === null) {
    return message('Invalid form data', 400, cors);
  }

  // Everything except the two named fields, mirroring `#[serde(flatten)]`.
  const fields = new Map<string, string>();
  for (const [key, value] of form) {
    if (key === 'g-recaptcha-response' || key === 'site') continue;
    fields.set(key, value);
  }

  if (!SITE_NAME_REGEX.test(site)) {
    return message('Invalid site name format', 400, cors);
  }

  // NOTE: matches the Rust original, which only ever checked a lowercase
  // "email" field. The stead. form posts "Email", so it is not validated here.
  const email = fields.get('email');
  if (email !== undefined && !EMAIL_REGEX.test(email)) {
    return message('Invalid email format', 400, cors);
  }

  if (token.trim() === '') {
    return message('Captcha response is required', 400, cors);
  }

  const siteUpper = site.toUpperCase();
  const siteKey = env[`${siteUpper}_RECAPTCHA_SITE_KEY`];
  if (!siteKey) {
    return message('Site not found or not configured', 401, cors);
  }

  const base =
    env.RECAPTCHA_API_BASE ?? 'https://recaptchaenterprise.googleapis.com';
  const assessUrl = `${base}/v1/projects/${env.GOOGLE_PROJECT_ID}/assessments?key=${env.GOOGLE_ENTERPRISE_API_KEY}`;

  let response: Response;
  try {
    response = await deps.fetch(assessUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event: { token, siteKey } }),
      signal: AbortSignal.timeout(RECAPTCHA_TIMEOUT_MS),
    });
  } catch (error) {
    deps.onError?.(error);
    return message('Captcha verification failed', 500, cors);
  }

  let assessment: any;
  try {
    assessment = await response.json();
  } catch (error) {
    deps.onError?.(error);
    return message('Failed to parse captcha response', 500, cors);
  }

  const isValid = assessment?.tokenProperties?.valid === true;

  if (!isValid) {
    deps.onError?.(AppError.captchaFailed(assessment));
    const reason =
      typeof assessment?.tokenProperties?.invalidReason === 'string'
        ? assessment.tokenProperties.invalidReason
        : 'Unknown error';
    return message(`Captcha verification failed: ${reason}`, 400, cors);
  }

  try {
    await sendEmailBasedOnSite(deps.emailSender, env, site, fields);
  } catch (error) {
    deps.onError?.(error);
    if (error instanceof AppError) {
      if (error.kind === 'SiteNotFound') {
        return message('Site not found', 401, cors);
      }
      if (error.kind === 'Validation') {
        return message(error.message, 400, cors);
      }
    }
    return message('Cannot send email', 500, cors);
  }

  return message('Captcha verification successful', 200, cors);
}

export async function sendEmailBasedOnSite(
  emailSender: EmailSender,
  env: Env,
  site: string,
  fields: Map<string, string>,
): Promise<void> {
  const siteUpper = site.toUpperCase();

  const emailTo = env[`${siteUpper}_EMAIL_TO`];
  const emailFrom = env[`${siteUpper}_EMAIL_FROM`];

  if (!emailTo || !emailFrom) throw AppError.siteNotFound();

  if (!EMAIL_REGEX.test(emailTo)) {
    throw AppError.validation(`Invalid recipient email: ${emailTo}`);
  }
  if (!EMAIL_REGEX.test(emailFrom)) {
    throw AppError.validation(`Invalid sender email: ${emailFrom}`);
  }

  const body = `You have a new contact request! Please see details below:\n${fieldsToString(fields)}`;

  await emailSender.send(
    env.RESEND_API_KEY,
    emailFrom,
    emailTo,
    'New lead from your website!',
    body,
  );
}

function fieldsToString(fields: Map<string, string>): string {
  let result = '';
  for (const [key, value] of fields) {
    result += `${key}: ${value}\n`;
  }
  return result;
}
