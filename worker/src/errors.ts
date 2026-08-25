/** Port of the `AxumError` enum from the original Rust service (src/error.rs). */

export type AppErrorKind =
  | 'SiteNotFound'
  | 'Validation'
  | 'CaptchaFailed'
  | 'Resend'
  | 'Server';

export class AppError extends Error {
  readonly kind: AppErrorKind;
  readonly detail?: unknown;

  constructor(kind: AppErrorKind, message: string, detail?: unknown) {
    super(message);
    this.name = `AppError(${kind})`;
    this.kind = kind;
    this.detail = detail;
  }

  static siteNotFound(): AppError {
    return new AppError('SiteNotFound', 'Site not found');
  }

  static validation(message: string): AppError {
    return new AppError('Validation', `Validation error: ${message}`);
  }

  static captchaFailed(response: unknown): AppError {
    return new AppError(
      'CaptchaFailed',
      `Captcha failed error. Response: ${JSON.stringify(response)}`,
      response,
    );
  }

  static resend(message: string): AppError {
    return new AppError('Resend', `Resend error: ${message}`);
  }
}
