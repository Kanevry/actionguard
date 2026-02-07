import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { nextAuth } from "../src/auth/next-auth";

function createTestJwt(payload: Record<string, unknown>, secret: string): string {
	const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
	const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
	const signature = createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
	return `${header}.${body}.${signature}`;
}

const TEST_SECRET = "next-auth-test-secret-key";

describe("nextAuth", () => {
	it("should throw if neither secret nor sessionEndpoint provided", () => {
		expect(() => nextAuth({})).toThrow(
			"nextAuth requires at least one of `secret` (for JWT verification) " +
				"or `sessionEndpoint` (for session fetching)",
		);
	});

	it("should throw with no arguments", () => {
		expect(() => nextAuth()).toThrow();
	});

	it("should not throw when secret is provided", () => {
		expect(() => nextAuth({ secret: TEST_SECRET })).not.toThrow();
	});

	it("should not throw when sessionEndpoint is provided", () => {
		expect(() =>
			nextAuth({ sessionEndpoint: "http://localhost:3000/api/auth/session" }),
		).not.toThrow();
	});

	it("should not throw when both secret and sessionEndpoint are provided", () => {
		expect(() =>
			nextAuth({ secret: TEST_SECRET, sessionEndpoint: "http://localhost:3000/api/auth/session" }),
		).not.toThrow();
	});

	describe("JWT mode (with secret)", () => {
		it("should return null for missing cookie header", async () => {
			const provider = nextAuth({ secret: TEST_SECRET });
			const headers = new Headers();
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null when session token cookie is not present", async () => {
			const provider = nextAuth({ secret: TEST_SECRET, secure: false });
			const headers = new Headers({ cookie: "other-cookie=value" });
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null for expired JWT", async () => {
			const token = createTestJwt(
				{
					sub: "user-123",
					name: "Expired User",
					email: "expired@example.com",
					exp: Math.floor(Date.now() / 1000) - 3600,
				},
				TEST_SECRET,
			);
			const provider = nextAuth({ secret: TEST_SECRET, secure: false });
			const headers = new Headers({
				cookie: `next-auth.session-token=${token}`,
			});
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return user for valid JWT", async () => {
			const token = createTestJwt(
				{
					sub: "user-jwt-456",
					name: "JWT User",
					email: "jwt@example.com",
					image: "https://example.com/avatar.jpg",
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				TEST_SECRET,
			);
			const provider = nextAuth({ secret: TEST_SECRET, secure: false });
			const headers = new Headers({
				cookie: `next-auth.session-token=${token}`,
			});
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.id).toBe("user-jwt-456");
			expect(result!.name).toBe("JWT User");
			expect(result!.email).toBe("jwt@example.com");
			expect(result!.image).toBe("https://example.com/avatar.jpg");
		});

		it("should map picture claim to image field", async () => {
			const token = createTestJwt(
				{
					sub: "user-pic",
					name: "Picture User",
					picture: "https://example.com/pic.jpg",
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				TEST_SECRET,
			);
			const provider = nextAuth({ secret: TEST_SECRET, secure: false });
			const headers = new Headers({
				cookie: `next-auth.session-token=${token}`,
			});
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.image).toBe("https://example.com/pic.jpg");
		});

		it("should carry over additional custom claims", async () => {
			const token = createTestJwt(
				{
					sub: "user-custom",
					name: "Custom User",
					email: "custom@example.com",
					role: "admin",
					orgId: "org-123",
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				TEST_SECRET,
			);
			const provider = nextAuth({ secret: TEST_SECRET, secure: false });
			const headers = new Headers({
				cookie: `next-auth.session-token=${token}`,
			});
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.role).toBe("admin");
			expect(result!.orgId).toBe("org-123");
		});

		describe("cookie name auto-detection", () => {
			it("should use secure cookie name when secure is true", async () => {
				const token = createTestJwt(
					{
						sub: "user-secure",
						name: "Secure User",
						exp: Math.floor(Date.now() / 1000) + 3600,
					},
					TEST_SECRET,
				);
				const provider = nextAuth({ secret: TEST_SECRET, secure: true });
				const headers = new Headers({
					cookie: `__Secure-next-auth.session-token=${token}`,
				});
				const result = await provider.resolve(headers);
				expect(result).not.toBeNull();
				expect(result!.id).toBe("user-secure");
			});

			it("should use non-secure cookie name when secure is false", async () => {
				const token = createTestJwt(
					{
						sub: "user-nonsecure",
						name: "Non-Secure User",
						exp: Math.floor(Date.now() / 1000) + 3600,
					},
					TEST_SECRET,
				);
				const provider = nextAuth({ secret: TEST_SECRET, secure: false });
				const headers = new Headers({
					cookie: `next-auth.session-token=${token}`,
				});
				const result = await provider.resolve(headers);
				expect(result).not.toBeNull();
				expect(result!.id).toBe("user-nonsecure");
			});

			it("should not find secure cookie when looking for non-secure name", async () => {
				const token = createTestJwt(
					{
						sub: "user-mismatch",
						exp: Math.floor(Date.now() / 1000) + 3600,
					},
					TEST_SECRET,
				);
				const provider = nextAuth({ secret: TEST_SECRET, secure: false });
				const headers = new Headers({
					cookie: `__Secure-next-auth.session-token=${token}`,
				});
				const result = await provider.resolve(headers);
				expect(result).toBeNull();
			});
		});

		it("should support custom cookie name", async () => {
			const token = createTestJwt(
				{
					sub: "user-custom-cookie",
					name: "Custom Cookie User",
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				TEST_SECRET,
			);
			const provider = nextAuth({ secret: TEST_SECRET, cookieName: "my-session" });
			const headers = new Headers({
				cookie: `my-session=${token}`,
			});
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.id).toBe("user-custom-cookie");
		});

		it("should return null for JWT with wrong signature", async () => {
			const token = createTestJwt(
				{
					sub: "user-wrong-sig",
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				"wrong-secret-key",
			);
			const provider = nextAuth({ secret: TEST_SECRET, secure: false });
			const headers = new Headers({
				cookie: `next-auth.session-token=${token}`,
			});
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null for malformed JWT (not 3 parts)", async () => {
			const provider = nextAuth({ secret: TEST_SECRET, secure: false });
			const headers = new Headers({
				cookie: "next-auth.session-token=not-a-jwt",
			});
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});
	});

	describe("session endpoint mode", () => {
		let mockFetch: ReturnType<typeof vi.fn>;
		const SESSION_ENDPOINT = "http://localhost:3000/api/auth/session";

		beforeEach(() => {
			mockFetch = vi.fn();
			vi.stubGlobal("fetch", mockFetch);
		});

		afterEach(() => {
			vi.unstubAllGlobals();
		});

		it("should return user on successful response", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: async () => ({
					user: {
						id: "user-session-123",
						name: "Session User",
						email: "session@example.com",
						image: null,
					},
					expires: "2026-12-31T00:00:00.000Z",
				}),
			});

			const provider = nextAuth({ sessionEndpoint: SESSION_ENDPOINT, secure: false });
			const headers = new Headers({
				cookie: "next-auth.session-token=some-encrypted-token",
			});
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.id).toBe("user-session-123");
			expect(result!.name).toBe("Session User");
			expect(result!.email).toBe("session@example.com");
		});

		it("should return null on failed fetch (non-200)", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: false,
				status: 401,
			});

			const provider = nextAuth({ sessionEndpoint: SESSION_ENDPOINT, secure: false });
			const headers = new Headers({
				cookie: "next-auth.session-token=invalid-token",
			});
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null on network error", async () => {
			mockFetch.mockRejectedValueOnce(new Error("Connection refused"));

			const provider = nextAuth({ sessionEndpoint: SESSION_ENDPOINT, secure: false });
			const headers = new Headers({
				cookie: "next-auth.session-token=some-token",
			});
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should forward cookie header to session endpoint", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: async () => ({
					user: { id: "user-fwd", name: "Forward User" },
					expires: "2026-12-31T00:00:00.000Z",
				}),
			});

			const cookieValue = "next-auth.session-token=abc123; other-cookie=xyz";
			const provider = nextAuth({ sessionEndpoint: SESSION_ENDPOINT, secure: false });
			const headers = new Headers({
				cookie: cookieValue,
			});
			await provider.resolve(headers);

			expect(mockFetch).toHaveBeenCalledWith(SESSION_ENDPOINT, {
				method: "GET",
				headers: {
					cookie: cookieValue,
				},
			});
		});

		it("should return null when no cookie header is present", async () => {
			const provider = nextAuth({ sessionEndpoint: SESSION_ENDPOINT });
			const headers = new Headers();
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
			expect(mockFetch).not.toHaveBeenCalled();
		});

		it("should return null when session response has no user object", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: async () => ({
					expires: "2026-12-31T00:00:00.000Z",
				}),
			});

			const provider = nextAuth({ sessionEndpoint: SESSION_ENDPOINT, secure: false });
			const headers = new Headers({
				cookie: "next-auth.session-token=some-token",
			});
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});
	});

	describe("fallback behavior (both secret and sessionEndpoint)", () => {
		let mockFetch: ReturnType<typeof vi.fn>;
		const SESSION_ENDPOINT = "http://localhost:3000/api/auth/session";

		beforeEach(() => {
			mockFetch = vi.fn();
			vi.stubGlobal("fetch", mockFetch);
		});

		afterEach(() => {
			vi.unstubAllGlobals();
		});

		it("should prefer JWT when valid and fall back to session on failure", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: async () => ({
					user: { id: "user-fallback", name: "Fallback User" },
					expires: "2026-12-31T00:00:00.000Z",
				}),
			});

			const provider = nextAuth({
				secret: TEST_SECRET,
				sessionEndpoint: SESSION_ENDPOINT,
				secure: false,
			});

			// Use an invalid JWT (wrong secret) so JWT verification fails -> fallback to session
			const headers = new Headers({
				cookie: "next-auth.session-token=not.a.valid-jwt",
			});
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.id).toBe("user-fallback");
			expect(mockFetch).toHaveBeenCalled();
		});

		it("should use JWT and skip session endpoint when JWT is valid", async () => {
			const token = createTestJwt(
				{
					sub: "user-jwt-preferred",
					name: "JWT Preferred",
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				TEST_SECRET,
			);

			const provider = nextAuth({
				secret: TEST_SECRET,
				sessionEndpoint: SESSION_ENDPOINT,
				secure: false,
			});

			const headers = new Headers({
				cookie: `next-auth.session-token=${token}`,
			});
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.id).toBe("user-jwt-preferred");
			expect(mockFetch).not.toHaveBeenCalled();
		});
	});
});
