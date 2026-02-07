import type { ZodSchema, z } from "zod";

export interface AuthProvider<TUser = unknown> {
	resolve: (headers: Headers) => Promise<TUser | null>;
}

export interface RateLimitConfig {
	maxRequests: number;
	window: string;
	store?: "memory" | object;
	identifier?: (ctx: MiddlewareContext) => string;
}

export interface AuditConfig {
	action: string;
	resource: string;
	adapter?: "console" | object;
	piiMasking?: boolean;
}

export interface CsrfConfig {
	enabled?: boolean;
	cookieName?: string;
	headerName?: string;
}

export interface ActionGuardConfig {
	auth?: AuthProvider;
	rateLimit?: {
		store?: "memory" | object;
		defaultWindow?: string;
		defaultMaxRequests?: number;
	};
	audit?: {
		adapter?: "console" | object;
		piiMasking?: boolean;
	};
	csrf?: CsrfConfig;
}

export interface MiddlewareContext<TUser = unknown, TInput = unknown> {
	user: TUser | null;
	input: TInput;
	headers: Headers;
	metadata: Record<string, unknown>;
}

export type Middleware<TCtx = MiddlewareContext> = (
	ctx: TCtx,
	next: () => Promise<void>,
) => Promise<void>;

export type ActionResult<T> =
	| { success: true; data: T }
	| { success: false; error: string; code?: string };

export interface ActionGuardInstance {
	auth: () => ActionBuilder;
	schema: <T extends ZodSchema>(schema: T) => ActionBuilder<z.infer<T>>;
	rateLimit: (config: RateLimitConfig) => ActionBuilder;
	audit: (config: AuditConfig) => ActionBuilder;
	csrf: () => ActionBuilder;
	action: <T>(
		handler: (params: { input: unknown; ctx: MiddlewareContext }) => Promise<T>,
	) => (...args: unknown[]) => Promise<ActionResult<T>>;
}

export interface ActionBuilder<TInput = unknown, TUser = unknown> {
	auth: () => ActionBuilder<TInput, TUser>;
	schema: <T extends ZodSchema>(schema: T) => ActionBuilder<z.infer<T>, TUser>;
	rateLimit: (config: RateLimitConfig) => ActionBuilder<TInput, TUser>;
	audit: (config: AuditConfig) => ActionBuilder<TInput, TUser>;
	csrf: () => ActionBuilder<TInput, TUser>;
	sanitize: () => ActionBuilder<TInput, TUser>;
	action: <T>(
		handler: (params: { input: TInput; ctx: MiddlewareContext<TUser, TInput> }) => Promise<T>,
	) => (...args: unknown[]) => Promise<ActionResult<T>>;
}
