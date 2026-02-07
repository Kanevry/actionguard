import { describe, expect, it } from "vitest";
import { customAuth } from "../src/auth/custom";
import { createActionGuard } from "../src/builder";

describe("createActionGuard", () => {
	it("should create a guard instance", () => {
		const guard = createActionGuard();
		expect(guard).toBeDefined();
		expect(guard.auth).toBeTypeOf("function");
		expect(guard.schema).toBeTypeOf("function");
		expect(guard.action).toBeTypeOf("function");
	});

	it("should execute a simple action", async () => {
		const guard = createActionGuard();
		const myAction = guard.action(async ({ input }) => {
			return { result: input };
		});

		const result = await myAction("test");
		expect(result).toEqual({ success: true, data: { result: "test" } });
	});

	it("should fail auth when no provider configured", async () => {
		const guard = createActionGuard();
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

	it("should pass auth with custom provider", async () => {
		const guard = createActionGuard({
			auth: customAuth(async () => ({ id: "1", name: "Test User" })),
		});

		const myAction = guard.auth().action(async ({ ctx }) => {
			return { user: ctx.user };
		});

		const result = await myAction();
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.user).toEqual({ id: "1", name: "Test User" });
		}
	});

	it("should reject when auth returns null", async () => {
		const guard = createActionGuard({
			auth: customAuth(async () => null),
		});

		const myAction = guard.auth().action(async () => {
			return { ok: true };
		});

		const result = await myAction();
		expect(result).toEqual({
			success: false,
			error: "Unauthorized",
			code: "AUTH_FAILED",
		});
	});

	it("should chain multiple middlewares", async () => {
		const guard = createActionGuard({
			auth: customAuth(async () => ({ id: "1" })),
		});

		const myAction = guard
			.auth()
			.audit({ action: "TEST", resource: "test" })
			.action(async ({ ctx }) => {
				return { user: ctx.user, hasAudit: !!ctx.metadata.audit };
			});

		const result = await myAction();
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.hasAudit).toBe(true);
		}
	});
});
