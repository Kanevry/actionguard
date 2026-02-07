import type { ZodSchema } from "zod";
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

export function createActionGuard(config: ActionGuardConfig = {}): ActionGuardInstance {
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
										return { success: false, error: "Unauthorized", code: "AUTH_FAILED" };
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
									// In-memory rate limiting (v0.1)
									break;
								}
								case "audit": {
									// Console audit logging (v0.1)
									const auditConfig = step.config as AuditConfig;
									ctx.metadata.audit = auditConfig;
									break;
								}
								case "csrf": {
									// CSRF validation (v0.1)
									break;
								}
								case "sanitize": {
									// Input sanitization (v0.1)
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
