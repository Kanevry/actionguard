import type { ZodSchema } from "zod";
import { validateCsrf } from "./csrf";
import { createRateLimiter } from "./rate-limit";
import { sanitizeInput } from "./sanitize";
import type {
	ActionBuilder,
	ActionGuardConfig,
	ActionGuardInstance,
	ActionResult,
	AuditConfig,
	MiddlewareContext,
	RateLimitConfig,
} from "./types";

interface PipelineStep {
	type: "auth" | "schema" | "rateLimit" | "audit" | "csrf" | "sanitize";
	config?: unknown;
}

type RateLimiterFn = ReturnType<typeof createRateLimiter>;

/**
 * Resolve a rate-limit key from the middleware context.
 * Priority: per-action identifier fn > user ID > IP from headers > "anonymous".
 */
function resolveRateLimitKey(ctx: MiddlewareContext, rlConfig: RateLimitConfig): string {
	if (rlConfig.identifier) {
		return rlConfig.identifier(ctx);
	}

	if (ctx.user) {
		return `user:${String(ctx.user)}`;
	}

	const forwarded = ctx.headers.get("x-forwarded-for");
	if (forwarded) {
		return `ip:${forwarded.split(",")[0].trim()}`;
	}

	const realIp = ctx.headers.get("x-real-ip");
	if (realIp) {
		return `ip:${realIp.trim()}`;
	}

	return "anonymous";
}

export function createActionGuard(config: ActionGuardConfig = {}): ActionGuardInstance {
	// Cache rate limiter instances per step config object to avoid recreation on every request.
	const rateLimiterCache = new Map<RateLimitConfig, RateLimiterFn>();

	function getOrCreateLimiter(rlConfig: RateLimitConfig): RateLimiterFn {
		let limiter = rateLimiterCache.get(rlConfig);
		if (limiter) {
			return limiter;
		}

		const globalRl = config.rateLimit;

		limiter = createRateLimiter({
			maxRequests: rlConfig.maxRequests ?? globalRl?.defaultMaxRequests ?? 100,
			window: rlConfig.window ?? globalRl?.defaultWindow ?? "1m",
			store:
				rlConfig.store && typeof rlConfig.store === "object"
					? (rlConfig.store as Parameters<typeof createRateLimiter>[0]["store"])
					: globalRl?.store && typeof globalRl.store === "object"
						? (globalRl.store as Parameters<typeof createRateLimiter>[0]["store"])
						: undefined,
		});

		rateLimiterCache.set(rlConfig, limiter);
		return limiter;
	}

	function createBuilder(steps: PipelineStep[] = []): ActionBuilder {
		const builder: ActionBuilder = {
			auth() {
				return createBuilder([...steps, { type: "auth" }]);
			},
			schema(schema: ZodSchema) {
				return createBuilder([...steps, { type: "schema", config: schema }]);
			},
			rateLimit(rlConfig: RateLimitConfig) {
				return createBuilder([...steps, { type: "rateLimit", config: rlConfig }]);
			},
			audit(auditConfig: AuditConfig) {
				return createBuilder([...steps, { type: "audit", config: auditConfig }]);
			},
			csrf() {
				return createBuilder([...steps, { type: "csrf" }]);
			},
			sanitize() {
				return createBuilder([...steps, { type: "sanitize" }]);
			},
			action<T>(
				handler: (params: { input: unknown; ctx: MiddlewareContext }) => Promise<T>,
			): (...args: unknown[]) => Promise<ActionResult<T>> {
				return async (...args: unknown[]): Promise<ActionResult<T>> => {
					const input = args[0];
					const ctx: MiddlewareContext = {
						user: null,
						input,
						headers: new Headers(),
						metadata: {},
					};

					try {
						for (const step of steps) {
							switch (step.type) {
								case "auth": {
									if (!config.auth) {
										throw new Error("Auth provider not configured");
									}
									const user = await config.auth.resolve(ctx.headers);
									if (!user) {
										return {
											success: false,
											error: "Unauthorized",
											code: "AUTH_FAILED",
										};
									}
									ctx.user = user;
									break;
								}
								case "schema": {
									const schema = step.config as ZodSchema;
									const result = schema.safeParse(ctx.input);
									if (!result.success) {
										return {
											success: false,
											error: "Validation failed",
											code: "VALIDATION_ERROR",
										};
									}
									ctx.input = result.data;
									break;
								}
								case "rateLimit": {
									const rlConfig = step.config as RateLimitConfig;
									const limiter = getOrCreateLimiter(rlConfig);
									const key = resolveRateLimitKey(ctx, rlConfig);
									const rlResult = await limiter(key);
									if (!rlResult.allowed) {
										return {
											success: false,
											error: "Rate limit exceeded",
											code: "RATE_LIMITED",
										};
									}
									ctx.metadata.rateLimit = {
										remaining: rlResult.remaining,
										resetAt: rlResult.resetAt.toISOString(),
									};
									break;
								}
								case "audit": {
									// Console audit logging (v0.1)
									const auditConfig = step.config as AuditConfig;
									ctx.metadata.audit = auditConfig;
									break;
								}
								case "csrf": {
									const csrfResult = validateCsrf(ctx.headers, config.csrf);
									if (!csrfResult.valid) {
										return {
											success: false,
											error: csrfResult.error ?? "CSRF validation failed",
											code: "CSRF_FAILED",
										};
									}
									break;
								}
								case "sanitize": {
									ctx.input = sanitizeInput(ctx.input);
									break;
								}
							}
						}

						const data = await handler({ input: ctx.input, ctx });

						// Post-execution audit log
						if (ctx.metadata.audit) {
							const auditConfig = ctx.metadata.audit as AuditConfig;
							console.log(
								JSON.stringify({
									timestamp: new Date().toISOString(),
									action: auditConfig.action,
									resource: auditConfig.resource,
									userId: ctx.user ? String(ctx.user) : "anonymous",
									success: true,
								}),
							);
						}

						return { success: true, data };
					} catch (error) {
						// Never leak internal errors
						const message = error instanceof Error ? error.message : "Internal error";
						return { success: false, error: message, code: "INTERNAL_ERROR" };
					}
				};
			},
		};

		return builder;
	}

	return {
		auth: () => createBuilder([{ type: "auth" }]),
		schema: (schema) => createBuilder([{ type: "schema", config: schema }]),
		rateLimit: (rlConfig) => createBuilder([{ type: "rateLimit", config: rlConfig }]),
		audit: (auditConfig) => createBuilder([{ type: "audit", config: auditConfig }]),
		csrf: () => createBuilder([{ type: "csrf" }]),
		action: (handler) => createBuilder().action(handler),
	};
}
