// Auth providers
export { customAuth } from "./auth/custom";
export type { NextAuthConfig, NextAuthUser } from "./auth/next-auth";
export { nextAuth } from "./auth/next-auth";
export type { SupabaseAuthConfig, SupabaseUser } from "./auth/supabase";
export { supabaseAuth } from "./auth/supabase";

// Builder
export { createActionGuard } from "./builder";

// CSRF
export type { CsrfValidationConfig } from "./csrf";
export {
	buildCsrfCookieHeader,
	generateCsrfToken,
	getCsrfTokenFromCookie,
	getCsrfTokenFromHeaders,
	validateCsrf,
} from "./csrf";

// Rate limiting
export type { RateLimiterOptions, RateLimitResult, RateLimitStore } from "./rate-limit";
export { createRateLimiter, MemoryRateLimitStore, parseWindow } from "./rate-limit";

// Sanitization
export type { SanitizeConfig } from "./sanitize";
export { escapeHtml, sanitizeInput, sanitizeValue } from "./sanitize";

// Types
export type {
	ActionBuilder,
	ActionGuardConfig,
	ActionGuardInstance,
	ActionResult,
	AuditConfig,
	AuthProvider,
	CsrfConfig,
	Middleware,
	MiddlewareContext,
	RateLimitConfig,
} from "./types";
