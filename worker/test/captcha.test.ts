import { describe, expect, it, vi } from 'vitest';
import { handle, type Deps, type EmailSender, type Env } from '../src/app';

/** Ports the #[cfg(test)] suite from ../src/main.rs. */

interface SentEmail {
  apiKey: string;
  from: string;
  to: string;
  subject: string;
  body: string;
}

class MockEmailSender implements EmailSender {
  readonly sent: SentEmail[] = [];
  constructor(private readonly shouldFail = false) {}

  async send(
    apiKey: string,
    from: string,
    to: string,
    subject: string,
    body: string,
  ): Promise<void> {
    if (this.shouldFail) throw new Error('Mock email failure');
    this.sent.push({ apiKey, from, to, subject, body });
  }
}

function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    GOOGLE_ENTERPRISE_API_KEY: 'test-google-key',
    GOOGLE_PROJECT_ID: 'test-project',
    RESEND_API_KEY: 'test-resend-key',
    ALLOWED_ORIGINS: 'https://stead.africa,https://donaldson.africa',
    RECAPTCHA_API_BASE: 'https://recaptcha.test',
    TESTSITE_RECAPTCHA_SITE_KEY: 'test-site-key',
    TESTSITE_EMAIL_TO: 'to@example.com',
    TESTSITE_EMAIL_FROM: 'from@example.com',
    ...overrides,
  } as Env;
}

/** Stands in for the wiremock server the Rust tests used. */
function recaptchaStub(payload: unknown, ok = true): typeof fetch {
  return vi.fn(async () =>
    new Response(JSON.stringify(payload), {
      status: ok ? 200 : 500,
      headers: { 'Content-Type': 'application/json' },
    }),
  ) as unknown as typeof fetch;
}

const VALID_TOKEN = { tokenProperties: { valid: true } };
const INVALID_TOKEN = {
  tokenProperties: { valid: false, invalidReason: 'EXPIRED' },
};

function makeDeps(overrides: Partial<Deps> = {}): Deps {
  return {
    emailSender: new MockEmailSender(),
    fetch: recaptchaStub(VALID_TOKEN),
    onError: vi.fn(),
    ...overrides,
  };
}

function postCaptcha(fields: Record<string, string>): Request {
  return new Request('https://captcha.stead.africa/captcha', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  });
}

describe('routing', () => {
  it('returns Healthy on GET /health', async () => {
    const res = await handle(
      new Request('https://captcha.stead.africa/health'),
      makeEnv(),
      makeDeps(),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ message: 'Healthy' });
  });

  it('404s an unknown path and 405s a wrong method', async () => {
    const env = makeEnv();
    const notFound = await handle(
      new Request('https://captcha.stead.africa/nope'),
      env,
      makeDeps(),
    );
    expect(notFound.status).toBe(404);

    const wrongMethod = await handle(
      new Request('https://captcha.stead.africa/captcha'),
      env,
      makeDeps(),
    );
    expect(wrongMethod.status).toBe(405);
  });
});

describe('request validation', () => {
  it('rejects an invalid site name', async () => {
    const res = await handle(
      postCaptcha({ 'g-recaptcha-response': 'tok', site: 'bad site!' }),
      makeEnv(),
      makeDeps(),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ message: 'Invalid site name format' });
  });

  it('rejects an empty captcha token', async () => {
    const res = await handle(
      postCaptcha({ 'g-recaptcha-response': '   ', site: 'testsite' }),
      makeEnv(),
      makeDeps(),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      message: 'Captcha response is required',
    });
  });

  it('rejects a malformed email field', async () => {
    const res = await handle(
      postCaptcha({
        'g-recaptcha-response': 'tok',
        site: 'testsite',
        email: 'not-an-email',
      }),
      makeEnv(),
      makeDeps(),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ message: 'Invalid email format' });
  });

  it('rejects a body missing the required named fields', async () => {
    const res = await handle(
      postCaptcha({ site: 'testsite' }),
      makeEnv(),
      makeDeps(),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ message: 'Invalid form data' });
  });

  it('rejects a body over 1 MiB', async () => {
    const request = new Request('https://captcha.stead.africa/captcha', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': String(2 * 1024 * 1024),
      },
      body: 'x'.repeat(16),
    });
    const res = await handle(request, makeEnv(), makeDeps());
    expect(res.status).toBe(413);
  });
});

describe('site configuration', () => {
  it('401s a site with no reCAPTCHA site key', async () => {
    const res = await handle(
      postCaptcha({ 'g-recaptcha-response': 'tok', site: 'unknownsite' }),
      makeEnv(),
      makeDeps(),
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({
      message: 'Site not found or not configured',
    });
  });

  it('401s when the site has a key but no email config', async () => {
    const env = makeEnv({ TESTSITE_EMAIL_TO: undefined });
    const res = await handle(
      postCaptcha({ 'g-recaptcha-response': 'tok', site: 'testsite' }),
      env,
      makeDeps(),
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ message: 'Site not found' });
  });

  it('400s when the configured recipient address is malformed', async () => {
    const env = makeEnv({ TESTSITE_EMAIL_TO: 'garbage' });
    const res = await handle(
      postCaptcha({ 'g-recaptcha-response': 'tok', site: 'testsite' }),
      env,
      makeDeps(),
    );
    expect(res.status).toBe(400);
    const payload = (await res.json()) as { message: string };
    expect(payload.message).toContain('Invalid recipient email');
  });
});

describe('captcha verification', () => {
  it('sends the email on a valid token', async () => {
    const emailSender = new MockEmailSender();
    const res = await handle(
      postCaptcha({
        'g-recaptcha-response': 'tok',
        site: 'testsite',
        name: 'Daniel',
        email: 'daniel@example.com',
        message: 'Hello there',
      }),
      makeEnv(),
      makeDeps({ emailSender }),
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      message: 'Captcha verification successful',
    });

    expect(emailSender.sent).toHaveLength(1);
    const sent = emailSender.sent[0];
    expect(sent.to).toBe('to@example.com');
    expect(sent.from).toBe('from@example.com');
    expect(sent.subject).toBe('New lead from your website!');
    expect(sent.body).toContain('You have a new contact request!');
    expect(sent.body).toContain('name: Daniel');
    expect(sent.body).toContain('message: Hello there');
    // The two control fields must not leak into the email body.
    expect(sent.body).not.toContain('g-recaptcha-response');
    expect(sent.body).not.toContain('site: testsite');
  });

  it('calls Google with the site key and token', async () => {
    const fetchSpy = recaptchaStub(VALID_TOKEN);
    await handle(
      postCaptcha({ 'g-recaptcha-response': 'tok-123', site: 'testsite' }),
      makeEnv(),
      makeDeps({ fetch: fetchSpy }),
    );

    const [url, init] = (fetchSpy as unknown as ReturnType<typeof vi.fn>).mock
      .calls[0];
    expect(url).toBe(
      'https://recaptcha.test/v1/projects/test-project/assessments?key=test-google-key',
    );
    expect(JSON.parse(init.body)).toEqual({
      event: { token: 'tok-123', siteKey: 'test-site-key' },
    });
  });

  it('rejects an invalid token and surfaces the reason', async () => {
    const emailSender = new MockEmailSender();
    const res = await handle(
      postCaptcha({ 'g-recaptcha-response': 'tok', site: 'testsite' }),
      makeEnv(),
      makeDeps({ emailSender, fetch: recaptchaStub(INVALID_TOKEN) }),
    );

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      message: 'Captcha verification failed: EXPIRED',
    });
    expect(emailSender.sent).toHaveLength(0);
  });

  it('500s when the reCAPTCHA call itself fails', async () => {
    const onError = vi.fn();
    const failingFetch = vi.fn(async () => {
      throw new Error('network down');
    }) as unknown as typeof fetch;

    const res = await handle(
      postCaptcha({ 'g-recaptcha-response': 'tok', site: 'testsite' }),
      makeEnv(),
      makeDeps({ fetch: failingFetch, onError }),
    );

    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ message: 'Captcha verification failed' });
    expect(onError).toHaveBeenCalled();
  });

  it('500s when the reCAPTCHA response is not JSON', async () => {
    const badJson = vi.fn(
      async () => new Response('<html>nope</html>', { status: 200 }),
    ) as unknown as typeof fetch;

    const res = await handle(
      postCaptcha({ 'g-recaptcha-response': 'tok', site: 'testsite' }),
      makeEnv(),
      makeDeps({ fetch: badJson }),
    );

    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({
      message: 'Failed to parse captcha response',
    });
  });

  it('500s when sending the email fails', async () => {
    const res = await handle(
      postCaptcha({ 'g-recaptcha-response': 'tok', site: 'testsite' }),
      makeEnv(),
      makeDeps({ emailSender: new MockEmailSender(true) }),
    );

    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ message: 'Cannot send email' });
  });
});

describe('CORS', () => {
  it('echoes an allow-listed origin', async () => {
    const res = await handle(
      new Request('https://captcha.stead.africa/health', {
        headers: { Origin: 'https://stead.africa' },
      }),
      makeEnv(),
      makeDeps(),
    );
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
      'https://stead.africa',
    );
    expect(res.headers.get('Access-Control-Allow-Credentials')).toBe('true');
  });

  it('does not echo an unknown origin', async () => {
    const res = await handle(
      new Request('https://captcha.stead.africa/health', {
        headers: { Origin: 'https://evil.example' },
      }),
      makeEnv(),
      makeDeps(),
    );
    expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();
  });

  it('answers a preflight', async () => {
    const res = await handle(
      new Request('https://captcha.stead.africa/captcha', {
        method: 'OPTIONS',
        headers: { Origin: 'https://donaldson.africa' },
      }),
      makeEnv(),
      makeDeps(),
    );
    expect(res.status).toBe(204);
    expect(res.headers.get('Access-Control-Allow-Methods')).toContain('POST');
  });
});
