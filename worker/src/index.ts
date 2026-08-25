import * as Sentry from '@sentry/cloudflare';
import { handle, ResendEmailSender, type Env } from './app';

/**
 * Worker entrypoint. All request handling lives in ./app.ts so it can be
 * tested without the workerd runtime; this file only wires up dependencies.
 */
const handler = {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handle(request, env, {
      emailSender: new ResendEmailSender(fetch),
      fetch,
      onError: (error) => {
        console.error(error);
        Sentry.captureException(error);
      },
    });
  },
} satisfies ExportedHandler<Env>;

export default Sentry.withSentry(
  (env: Env) => ({
    // An empty DSN disables Sentry, so the Worker runs fine without it set.
    dsn: env.SENTRY_DSN ?? '',
    sendDefaultPii: false,
  }),
  handler,
);
