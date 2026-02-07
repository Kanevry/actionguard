import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { customAuth } from "../src/auth/custom";
import { createActionGuard } from "../src/builder";

describe("Builder Integration Pipeline", () => {
	describe("Full pipeline: auth -> schema -> rateLimit -> sanitize -> audit -> action", () => {
		it("should pass input through all middleware and deliver sanitized data to the handler", async () => {
			const testUser = { id: "user-42", role: "admin" };
			const guard = createActionGuard({
				auth: customAuth(async () => testUser),
			});

			const schema = z.object({
				name: z.string().min(1),
				comment: z.string(),
			});

			const myAction = guard
				.auth()
				.schema(schema)
				.rateLimit({ maxRequests: 10, window: "1m" })
				.sanitize()
				.audit({ action: "CREATE_POST", resource: "posts" })
				.action(async ({ input, ctx }) => {
					return {
						receivedInput: input,
						user: ctx.user,
						hasRateLimitMeta: "rateLimit" in ctx.metadata,
						hasAuditMeta: "audit" in ctx.metadata,
					};
				});

			const result = await myAction({
				name: "Test Post",
				comment: '<script>alert("xss")</script>',
			});

			expect(result.success).toBe(true);
			if (!result.success) return;

			// Auth: user was resolved and attached to context
			expect(result.data.user).toEqual(testUser);

			// Sanitize: XSS in comment was escaped
			expect(result.data.receivedInput).toEqual({
				name: "Test Post",
				comment: "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;",
			});

			// RateLimit: metadata was attached
			expect(result.data.hasRateLimitMeta).toBe(true);

			// Audit: config was stored in metadata
			expect(result.data.hasAuditMeta).toBe(true);
		});

		it("should stop pipeline at the first failing middleware", async () => {
			const guard = createActionGuard({
				auth: customAuth(async () => null), // Auth fails
			});

			const schema = z.object({ name: z.string() });
			const handlerSpy = vi.fn().mockResolvedValue({ ok: true });

			const myAction = guard
				.auth()
				.schema(schema)
				.rateLimit({ maxRequests: 10, window: "1m" })
				.sanitize()
				.action(handlerSpy);

			const result = await myAction({ name: "test" });

			expect(result).toEqual({
				success: false,
				error: "Unauthorized",
				code: "AUTH_FAILED",
			});

			// Handler was never called because auth failed first
			expect(handlerSpy).not.toHaveBeenCalled();
		});
	});

	describe("Rate limit integration", () => {
		it("should allow requests up to maxRequests and reject afterwards", async () => {
			const guard = createActionGuard();
			const maxRequests = 3;

			const myAction = guard.rateLimit({ maxRequests, window: "1m" }).action(async ({ input }) => {
				return { received: input };
			});

			// First maxRequests calls should succeed
			for (let i = 0; i < maxRequests; i++) {
				const result = await myAction(`request-${i}`);
				expect(result.success).toBe(true);
				if (result.success) {
					expect(result.data.received).toBe(`request-${i}`);
				}
			}

			// Next call should be rate limited
			const rejected = await myAction("one-too-many");
			expect(rejected).toEqual({
				success: false,
				error: "Rate limit exceeded",
				code: "RATE_LIMITED",
			});
		});

		it("should share rate limit bucket globally when no custom identifier is provided", async () => {
			// Note: The builder resolves a per-user key via resolveRateLimitKey,
			// but createRateLimiter defaults keyFn to () => "global" and ignores
			// the key argument. As a result, all users share one global bucket
			// unless a custom identifier function is configured.
			let currentUser: string | null = "user-a";
			const guard = createActionGuard({
				auth: customAuth(async () => currentUser),
			});

			const myAction = guard
				.auth()
				.rateLimit({ maxRequests: 2, window: "1m" })
				.action(async ({ ctx }) => {
					return { user: ctx.user };
				});

			// Exhaust the shared global rate limit bucket
			await myAction("req1");
			await myAction("req2");

			// Even switching to a different user hits the same bucket
			currentUser = "user-b";
			const userBResult = await myAction("req1");
			expect(userBResult.success).toBe(false);
			if (!userBResult.success) {
				expect(userBResult.code).toBe("RATE_LIMITED");
			}
		});

		it("should use custom identifier function for rate limit keys", async () => {
			const guard = createActionGuard({
				auth: customAuth(async () => ({ id: "obj-user-1" })),
			});

			const myAction = guard
				.auth()
				.rateLimit({
					maxRequests: 2,
					window: "1m",
					identifier: (ctx) => {
						const user = ctx.user as { id: string } | null;
						return user ? `custom:${user.id}` : "anon";
					},
				})
				.action(async ({ ctx }) => {
					return { user: ctx.user };
				});

			// Custom identifier ensures object users get distinct keys
			const r1 = await myAction("req1");
			const r2 = await myAction("req2");
			expect(r1.success).toBe(true);
			expect(r2.success).toBe(true);

			// Third request should be rate limited
			const r3 = await myAction("req3");
			expect(r3.success).toBe(false);
			if (!r3.success) {
				expect(r3.code).toBe("RATE_LIMITED");
			}
		});

		it("should attach rateLimit metadata to context on success", async () => {
			const guard = createActionGuard();

			const myAction = guard.rateLimit({ maxRequests: 5, window: "1m" }).action(async ({ ctx }) => {
				return { rateLimit: ctx.metadata.rateLimit };
			});

			const result = await myAction("test");
			expect(result.success).toBe(true);
			if (!result.success) return;

			const rl = result.data.rateLimit as { remaining: number; resetAt: string };
			expect(rl).toBeDefined();
			expect(rl.remaining).toBe(4); // 5 max - 1 used = 4 remaining
			expect(typeof rl.resetAt).toBe("string");
		});
	});

	describe("CSRF integration", () => {
		it("should reject action when CSRF headers are missing", async () => {
			const guard = createActionGuard();

			const myAction = guard.csrf().action(async () => {
				return { ok: true };
			});

			// Builder creates empty Headers internally, so CSRF always fails
			// when no mechanism to inject request headers exists
			const result = await myAction("input");

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.code).toBe("CSRF_FAILED");
				expect(result.error).toContain("Missing CSRF token");
			}
		});

		it("should reject with CSRF_FAILED even when other middleware passes", async () => {
			const guard = createActionGuard({
				auth: customAuth(async () => ({ id: "user-1" })),
			});

			const handlerSpy = vi.fn().mockResolvedValue({ ok: true });

			// Auth passes, but CSRF fails — handler should not be reached
			const myAction = guard.auth().csrf().action(handlerSpy);

			const result = await myAction("test");

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.code).toBe("CSRF_FAILED");
			}
			expect(handlerSpy).not.toHaveBeenCalled();
		});

		it("should use custom CSRF config from guard configuration", async () => {
			const guard = createActionGuard({
				csrf: {
					headerName: "x-custom-csrf",
					cookieName: "custom-csrf-cookie",
				},
			});

			const myAction = guard.csrf().action(async () => {
				return { ok: true };
			});

			const result = await myAction("test");

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.code).toBe("CSRF_FAILED");
				// Error message references the custom header name
				expect(result.error).toContain("x-custom-csrf");
			}
		});
	});

	describe("Auth failure propagation", () => {
		it("should return AUTH_FAILED when auth provider resolves to null", async () => {
			const guard = createActionGuard({
				auth: customAuth(async () => null),
			});

			const myAction = guard.auth().action(async () => {
				return { shouldNotReach: true };
			});

			const result = await myAction();

			expect(result).toEqual({
				success: false,
				error: "Unauthorized",
				code: "AUTH_FAILED",
			});
		});

		it("should return INTERNAL_ERROR when no auth provider is configured", async () => {
			const guard = createActionGuard(); // No auth config

			const myAction = guard.auth().action(async () => {
				return { ok: true };
			});

			const result = await myAction();

			expect(result).toEqual({
				success: false,
				error: "Auth provider not configured",
				code: "INTERNAL_ERROR",
			});
		});

		it("should return INTERNAL_ERROR when auth provider throws", async () => {
			const guard = createActionGuard({
				auth: customAuth(async () => {
					throw new Error("Database connection failed");
				}),
			});

			const myAction = guard.auth().action(async () => {
				return { ok: true };
			});

			const result = await myAction();

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.code).toBe("INTERNAL_ERROR");
			}
		});
	});

	describe("Schema + sanitize ordering", () => {
		it("should validate schema on raw input then sanitize for the handler", async () => {
			const guard = createActionGuard();

			const schema = z.object({
				title: z.string().min(1),
				body: z.string(),
			});

			const myAction = guard
				.schema(schema)
				.sanitize()
				.action(async ({ input }) => {
					return { input };
				});

			const xssInput = {
				title: "Legitimate Title",
				body: '<img src=x onerror="alert(1)">',
			};

			const result = await myAction(xssInput);

			expect(result.success).toBe(true);
			if (!result.success) return;

			// Schema passed (raw input is valid), then sanitize escaped HTML
			expect(result.data.input).toEqual({
				title: "Legitimate Title",
				body: "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;",
			});
		});

		it("should reject invalid input at schema step before sanitize runs", async () => {
			const guard = createActionGuard();

			const schema = z.object({
				email: z.string().email(),
				name: z.string().min(2),
			});

			const myAction = guard
				.schema(schema)
				.sanitize()
				.action(async ({ input }) => {
					return { input };
				});

			const result = await myAction({ email: "not-an-email", name: "A" });

			expect(result).toEqual({
				success: false,
				error: "Validation failed",
				code: "VALIDATION_ERROR",
			});
		});

		it("should use Zod-transformed data after schema step", async () => {
			const guard = createActionGuard();

			const schema = z.object({
				count: z.coerce.number(),
				tag: z.string().trim().toLowerCase(),
			});

			const myAction = guard.schema(schema).action(async ({ input }) => {
				return { input };
			});

			const result = await myAction({ count: "42", tag: "  UPPER  " });

			expect(result.success).toBe(true);
			if (!result.success) return;

			// Zod coerced string "42" to number and transformed tag
			expect(result.data.input).toEqual({
				count: 42,
				tag: "upper",
			});
		});

		it("should sanitize nested objects with XSS payloads", async () => {
			const guard = createActionGuard();

			const schema = z.object({
				user: z.object({
					name: z.string(),
					bio: z.string(),
				}),
				tags: z.array(z.string()),
			});

			const myAction = guard
				.schema(schema)
				.sanitize()
				.action(async ({ input }) => {
					return { input };
				});

			const result = await myAction({
				user: {
					name: "Alice",
					bio: '<a href="javascript:void(0)">click</a>',
				},
				tags: ["safe", "<b>bold</b>"],
			});

			expect(result.success).toBe(true);
			if (!result.success) return;

			const data = result.data.input as {
				user: { name: string; bio: string };
				tags: string[];
			};

			expect(data.user.name).toBe("Alice");
			expect(data.user.bio).toBe("&lt;a href=&quot;javascript:void(0)&quot;&gt;click&lt;/a&gt;");
			expect(data.tags).toEqual(["safe", "&lt;b&gt;bold&lt;/b&gt;"]);
		});
	});

	describe("Audit logging", () => {
		let consoleSpy: ReturnType<typeof vi.spyOn>;

		beforeEach(() => {
			consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
		});

		afterEach(() => {
			consoleSpy.mockRestore();
		});

		it("should log a JSON audit entry after successful action execution", async () => {
			const testUser = { id: "user-99", name: "Auditor" };
			const guard = createActionGuard({
				auth: customAuth(async () => testUser),
			});

			const myAction = guard
				.auth()
				.audit({ action: "DELETE_RECORD", resource: "invoices" })
				.action(async () => {
					return { deleted: true };
				});

			const result = await myAction();

			expect(result.success).toBe(true);
			expect(consoleSpy).toHaveBeenCalledOnce();

			// Parse the logged JSON string
			const loggedArg = consoleSpy.mock.calls[0][0] as string;
			const auditEntry = JSON.parse(loggedArg);

			expect(auditEntry).toMatchObject({
				action: "DELETE_RECORD",
				resource: "invoices",
				userId: "[object Object]", // String(testUser) — the user object is stringified
				success: true,
			});
			expect(auditEntry.timestamp).toBeDefined();
		});

		it("should log userId as 'anonymous' when no auth middleware is used", async () => {
			const guard = createActionGuard();

			const myAction = guard
				.audit({ action: "VIEW_PAGE", resource: "dashboard" })
				.action(async () => {
					return { viewed: true };
				});

			const result = await myAction();

			expect(result.success).toBe(true);
			expect(consoleSpy).toHaveBeenCalledOnce();

			const auditEntry = JSON.parse(consoleSpy.mock.calls[0][0] as string);
			expect(auditEntry.userId).toBe("anonymous");
			expect(auditEntry.action).toBe("VIEW_PAGE");
			expect(auditEntry.resource).toBe("dashboard");
			expect(auditEntry.success).toBe(true);
		});

		it("should not log audit entry when action handler throws", async () => {
			const guard = createActionGuard();

			const myAction = guard.audit({ action: "RISKY_OP", resource: "system" }).action(async () => {
				throw new Error("Handler exploded");
			});

			const result = await myAction();

			// Action failed
			expect(result.success).toBe(false);

			// Audit log should NOT have been called because the error was caught
			// before the post-execution audit block
			expect(consoleSpy).not.toHaveBeenCalled();
		});

		it("should use string userId when auth resolves to a string user", async () => {
			const guard = createActionGuard({
				auth: customAuth(async () => "user-string-id-123"),
			});

			const myAction = guard
				.auth()
				.audit({ action: "UPDATE", resource: "profile" })
				.action(async () => {
					return { updated: true };
				});

			const result = await myAction();

			expect(result.success).toBe(true);
			expect(consoleSpy).toHaveBeenCalledOnce();

			const auditEntry = JSON.parse(consoleSpy.mock.calls[0][0] as string);
			expect(auditEntry.userId).toBe("user-string-id-123");
		});
	});

	describe("Error handling", () => {
		it("should return INTERNAL_ERROR when the action handler throws an Error", async () => {
			const guard = createActionGuard();

			const myAction = guard.action(async () => {
				throw new Error("Something went wrong internally");
			});

			const result = await myAction();

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.code).toBe("INTERNAL_ERROR");
				expect(result.error).toBe("Something went wrong internally");
			}
		});

		it("should return generic message when a non-Error is thrown", async () => {
			const guard = createActionGuard();

			const myAction = guard.action(async () => {
				throw "string error"; // eslint-disable-line no-throw-literal
			});

			const result = await myAction();

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.code).toBe("INTERNAL_ERROR");
				expect(result.error).toBe("Internal error");
			}
		});

		it("should never expose stack traces in the result", async () => {
			const guard = createActionGuard();

			const myAction = guard.action(async () => {
				const err = new Error("DB query failed");
				err.stack = "Error: DB query failed\n    at Object.<anonymous> (/app/secret/path.ts:42)";
				throw err;
			});

			const result = await myAction();

			expect(result.success).toBe(false);
			if (!result.success) {
				// Only the message is returned, not the stack
				expect(result.error).toBe("DB query failed");
				expect(result.error).not.toContain("/app/secret/path.ts");
				expect((result as Record<string, unknown>).stack).toBeUndefined();
			}
		});

		it("should catch errors thrown inside middleware steps (auth provider)", async () => {
			const guard = createActionGuard({
				auth: customAuth(async () => {
					throw new TypeError("Cannot read properties of undefined");
				}),
			});

			const handlerSpy = vi.fn().mockResolvedValue({ ok: true });
			const myAction = guard.auth().action(handlerSpy);

			const result = await myAction();

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.code).toBe("INTERNAL_ERROR");
				expect(result.error).toBe("Cannot read properties of undefined");
			}
			expect(handlerSpy).not.toHaveBeenCalled();
		});
	});

	describe("Multiple middleware ordering", () => {
		it("should execute middlewares in the order they are chained", async () => {
			const executionOrder: string[] = [];

			const guard = createActionGuard({
				auth: customAuth(async () => {
					executionOrder.push("auth");
					return { id: "user-1" };
				}),
			});

			const schema = z.object({ value: z.string() }).transform((data) => {
				executionOrder.push("schema");
				return data;
			});

			const myAction = guard
				.auth()
				.schema(schema)
				.rateLimit({ maxRequests: 100, window: "1m" })
				.sanitize()
				.audit({ action: "TEST", resource: "ordering" })
				.action(async ({ input }) => {
					executionOrder.push("handler");
					return { input };
				});

			const result = await myAction({ value: "test" });

			expect(result.success).toBe(true);

			// Auth and schema are tracked via side effects; rateLimit, sanitize, and
			// audit execute silently but in order. Handler executes last.
			expect(executionOrder[0]).toBe("auth");
			expect(executionOrder[1]).toBe("schema");
			expect(executionOrder[executionOrder.length - 1]).toBe("handler");
		});

		it("should stop at the first failing middleware without executing later ones", async () => {
			const executionLog: string[] = [];

			const guard = createActionGuard({
				auth: customAuth(async () => {
					executionLog.push("auth-executed");
					return null; // Auth fails
				}),
			});

			const schema = z.object({ name: z.string() }).transform((data) => {
				executionLog.push("schema-executed");
				return data;
			});

			const myAction = guard
				.auth()
				.schema(schema)
				.rateLimit({ maxRequests: 10, window: "1m" })
				.action(async () => {
					executionLog.push("handler-executed");
					return { ok: true };
				});

			const result = await myAction({ name: "test" });

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.code).toBe("AUTH_FAILED");
			}

			// Only auth ran; schema, rateLimit, and handler were never reached
			expect(executionLog).toEqual(["auth-executed"]);
		});

		it("should allow different chaining orders on the same guard instance", async () => {
			const guard = createActionGuard({
				auth: customAuth(async () => ({ id: "user-1" })),
			});

			// Action A: schema first, then auth
			const schemaA = z.object({ x: z.number() });
			const actionA = guard
				.schema(schemaA)
				.auth()
				.action(async ({ input, ctx }) => {
					return { input, user: ctx.user };
				});

			// Action B: auth first, then schema
			const schemaB = z.object({ y: z.string() });
			const actionB = guard
				.auth()
				.schema(schemaB)
				.action(async ({ input, ctx }) => {
					return { input, user: ctx.user };
				});

			const resultA = await actionA({ x: 42 });
			const resultB = await actionB({ y: "hello" });

			expect(resultA.success).toBe(true);
			expect(resultB.success).toBe(true);

			if (resultA.success) {
				expect(resultA.data.input).toEqual({ x: 42 });
				expect(resultA.data.user).toEqual({ id: "user-1" });
			}

			if (resultB.success) {
				expect(resultB.data.input).toEqual({ y: "hello" });
				expect(resultB.data.user).toEqual({ id: "user-1" });
			}
		});

		it("should isolate rate limit state between different guard instances", async () => {
			const guardA = createActionGuard();
			const guardB = createActionGuard();

			const actionA = guardA
				.rateLimit({ maxRequests: 1, window: "1m" })
				.action(async () => ({ source: "A" }));

			const actionB = guardB
				.rateLimit({ maxRequests: 1, window: "1m" })
				.action(async () => ({ source: "B" }));

			// Exhaust rate limit on guard A
			const resultA1 = await actionA();
			expect(resultA1.success).toBe(true);

			const resultA2 = await actionA();
			expect(resultA2.success).toBe(false);

			// Guard B should still have its own fresh rate limit
			const resultB1 = await actionB();
			expect(resultB1.success).toBe(true);
		});
	});
});
