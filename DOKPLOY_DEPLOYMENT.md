# Dokploy Deployment Guide

## Overview
This Rust captcha verification service handles Google reCAPTCHA verification and email sending via SendGrid for multiple sites.

## Deployment Steps

### 1. Create Service in Dokploy

1. Log into your Dokploy dashboard
2. Create a new **Project** (or use existing "shared-services" project)
3. Add a new **Service** with these settings:
   - **Source**: GitHub Repository
   - **Repository**: `https://github.com/danieldonaldson/rust-captcha-verification`
   - **Branch**: `main`
   - **Build Type**: Dockerfile
   - **Dockerfile Path**: `./Dockerfile`

### 2. Configure Domain

1. In the service settings, add domain:
   - **Domain**: Your preferred subdomain (e.g., `captcha.yourdomain.com`)
   - **Port**: `2121`
   - **Protocol**: HTTPS (Dokploy will handle SSL)

2. Update your DNS:
   - Add an A record pointing to your Dokploy server IP
   - Or add a CNAME if using a subdomain

### 3. Environment Variables

Add the following environment variables in Dokploy:

#### Required for all deployments:
```
GRECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
SENTRY_DSN=your_sentry_dsn
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

**IMPORTANT**: `ALLOWED_ORIGINS` is a comma-separated list of domains that are allowed to make requests to this service. Add all your domains here.

#### Per-site configuration (add for each site):
For each site using the service, add three environment variables following this pattern:
```
{SITE_NAME_UPPERCASE}_SENDGRID_API_KEY=your_sendgrid_api_key
{SITE_NAME_UPPERCASE}_EMAIL_TO=recipient@example.com
{SITE_NAME_UPPERCASE}_EMAIL_FROM=noreply@example.com
```

Example for a site named "mysite":
```
MYSITE_SENDGRID_API_KEY=SG.xxxxx
MYSITE_EMAIL_TO=contact@mysite.com
MYSITE_EMAIL_FROM=noreply@mysite.com
```

### 4. Deploy

1. Click **Deploy** in Dokploy
2. Monitor the build logs
3. Once deployed, test the health endpoint: `https://your-captcha-domain.com/health`

## CORS Configuration

The service is configured to only allow requests from domains specified in the `ALLOWED_ORIGINS` environment variable. This provides security while allowing multiple sites to use the service.

**To configure allowed origins**, set the `ALLOWED_ORIGINS` environment variable in Dokploy:
```
ALLOWED_ORIGINS=https://example.com,https://www.example.com,https://another-site.com
```

**Note**:
- Each origin must include the full protocol (https://)
- No trailing slashes
- Comma-separated for multiple domains
- This variable is **required** - the service will not start without it

## Usage in Frontend

Update your website's contact form to post to:
```
https://your-captcha-domain.com/captcha
```

Example form data:
```
g-recaptcha-response: [token from Google reCAPTCHA]
site: mysite
name: John Doe
email: john@example.com
message: Your message here
```

The `site` parameter should match the uppercase prefix of your environment variables (e.g., "mysite" matches `MYSITE_SENDGRID_API_KEY`).

## Monitoring

- **Health Check**: `GET https://your-captcha-domain.com/health`
- **Logs**: View in Dokploy dashboard
- **Errors**: Tracked in Sentry (configured via `SENTRY_DSN`)

## Updating

1. Push changes to GitHub
2. Dokploy will auto-rebuild if webhook is configured
3. Or manually trigger rebuild in Dokploy dashboard
