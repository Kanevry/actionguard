<p align="center">
  <h1 align="center">ActionGuard</h1>
  <p align="center">Security middleware for Server Actions. Auth, rate limiting, audit logging — in one line of code.</p>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/actionguard"><img src="https://img.shields.io/npm/v/actionguard?color=blue" alt="npm version" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-5.7-blue" alt="TypeScript" /></a>
  <a href="https://github.com/actionguard/actionguard/actions"><img src="https://img.shields.io/github/actions/workflow/status/actionguard/actionguard/ci.yml?label=CI" alt="CI Status" /></a>
</p>

---

## Why

Next.js Server Actions are powerful — but they're raw database calls behind a POST endpoint. No auth check, no rate limiting, no audit trail. **One missing `if (!user)` and your data is exposed.**

ActionGuard wraps every Server Action in a composable security pipeline. Auth, rate limiting, CSRF protection, and audit logging — configured once, applied everywhere.

## Quick Start

```bash
npm install actionguard
```

```typescript
// lib/action-guard.ts
import { createActionGuard } from 'actionguard';
import { customAuth } from 'actionguard/auth/custom';

export const guard = createActionGuard({
  auth: customAuth(async (headers) => {
    // Your auth logic here
    return getUserFromSession(headers);
  }),
});
```

```typescript
// app/actions/invoices.ts
'use server';
import { guard } from '@/lib/action-guard';
import { z } from 'zod';

const DeleteSchema = z.object({ invoiceId: z.string().uuid() });

export const deleteInvoice = guard
  .auth()
  .schema(DeleteSchema)
  .rateLimit({ maxRequests: 10, window: '1m' })
  .audit({ action: 'DELETE', resource: 'invoices' })
  .action(async ({ input, ctx }) => {
    await db.invoices.softDelete(input.invoiceId);
    return { deleted: true };
  });
```

## Features

| Feature | Community (Free) | Pro |
|---------|-----------------|-----|
| Zod Schema Validation | ✅ | ✅ |
| Auth (Supabase, NextAuth, Custom) | ✅ 3 providers | ✅ 8+ providers |
| Rate Limiting | ✅ In-memory | ✅ Redis/Upstash |
| CSRF Protection | ✅ | ✅ |
| Input Sanitization | ✅ | ✅ |
| Audit Logging | ✅ Console | ✅ DB Adapters |
| PII Masking | — | ✅ |
| RBAC | ✅ Role match | ✅ Role hierarchy |
| GDPR/SOC2 Presets | — | ✅ |

## Auth Providers

```typescript
// Supabase
import { supabaseAuth } from 'actionguard/auth/supabase';

// NextAuth / Auth.js
import { nextAuth } from 'actionguard/auth/next-auth';

// Custom
import { customAuth } from 'actionguard/auth/custom';
```

## Documentation

Visit [actionguard.dev](https://actionguard.dev) for full documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

[MIT](LICENSE) — ActionGuard core is free and open source.

[@actionguard/pro](https://actionguard.dev/pro) is available under a commercial license.
