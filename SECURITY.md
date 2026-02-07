# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in ActionGuard, please report it responsibly.

**Do NOT open a public issue.**

Instead, email us at: **security@actionguard.dev**

We will acknowledge receipt within 48 hours and provide a detailed response within 5 business days.

## Disclosure Policy

- We will confirm the vulnerability and determine its impact.
- We will release a fix as soon as possible.
- We will credit the reporter (unless they prefer to remain anonymous).

## Security Best Practices

When using ActionGuard:

1. Always keep ActionGuard updated to the latest version.
2. Never commit `.env` files or API keys to your repository.
3. Use the CSRF middleware for state-changing actions.
4. Enable audit logging for sensitive operations.
5. Use rate limiting to prevent abuse.
