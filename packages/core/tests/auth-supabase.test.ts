import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { supabaseAuth } from "../src/auth/supabase";

function createTestJwt(payload: Record<string, unknown>, secret: string): string {
	const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
	const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
	const signature = createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
	return `${header}.${body}.${signature}`;
}

const TEST_SECRET = "super-secret-jwt-key-for-testing";
const TEST_URL = "https://myproject.supabase.co";
const TEST_ANON_KEY = "test-anon-key-123";

describe("supabaseAuth", () => {
	it("should return an AuthProvider with a resolve function", () => {
		const provider = supabaseAuth({ url: TEST_URL, anonKey: TEST_ANON_KEY });
		expect(provider).toBeDefined();
		expect(provider.resolve).toBeTypeOf("function");
	});

	describe("JWT mode (with jwtSecret)", () => {
		const provider = supabaseAuth({
			url: TEST_URL,
			anonKey: TEST_ANON_KEY,
			jwtSecret: TEST_SECRET,
		});

		it("should return null for missing Authorization header", async () => {
			const headers = new Headers();
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null for empty Authorization header", async () => {
			const headers = new Headers({ authorization: "" });
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null for malformed bearer token (no Bearer prefix)", async () => {
			const headers = new Headers({ authorization: "Basic abc123" });
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null for malformed bearer token (Bearer with no token)", async () => {
			const headers = new Headers({ authorization: "Bearer " });
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null for invalid JWT structure (not 3 parts)", async () => {
			const headers = new Headers({ authorization: "Bearer not.a.valid.jwt.token" });
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null for JWT with wrong signature", async () => {
			const token = createTestJwt(
				{
					sub: "user-123",
					email: "test@example.com",
					role: "authenticated",
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				"wrong-secret",
			);
			const headers = new Headers({ authorization: `Bearer ${token}` });
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null for expired JWT", async () => {
			const token = createTestJwt(
				{
					sub: "user-123",
					email: "test@example.com",
					role: "authenticated",
					exp: Math.floor(Date.now() / 1000) - 3600,
				},
				TEST_SECRET,
			);
			const headers = new Headers({ authorization: `Bearer ${token}` });
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return user for valid JWT", async () => {
			const token = createTestJwt(
				{
					sub: "user-abc-123",
					email: "user@example.com",
					role: "authenticated",
					app_metadata: { provider: "email" },
					user_metadata: { full_name: "Test User" },
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				TEST_SECRET,
			);
			const headers = new Headers({ authorization: `Bearer ${token}` });
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.id).toBe("user-abc-123");
			expect(result!.email).toBe("user@example.com");
			expect(result!.role).toBe("authenticated");
		});

		it("should return user with correct app_metadata and user_metadata", async () => {
			const token = createTestJwt(
				{
					sub: "user-456",
					email: "meta@example.com",
					role: "admin",
					app_metadata: { provider: "google", providers: ["google"] },
					user_metadata: { avatar_url: "https://example.com/avatar.png" },
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				TEST_SECRET,
			);
			const headers = new Headers({ authorization: `Bearer ${token}` });
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.app_metadata).toEqual({
				provider: "google",
				providers: ["google"],
			});
			expect(result!.user_metadata).toEqual({
				avatar_url: "https://example.com/avatar.png",
			});
		});

		it("should handle JWT without exp claim (no expiration)", async () => {
			const token = createTestJwt(
				{
					sub: "user-no-exp",
					email: "noexp@example.com",
					role: "authenticated",
				},
				TEST_SECRET,
			);
			const headers = new Headers({ authorization: `Bearer ${token}` });
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.id).toBe("user-no-exp");
		});

		it("should default app_metadata and user_metadata to empty objects", async () => {
			const token = createTestJwt(
				{
					sub: "user-minimal",
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				TEST_SECRET,
			);
			const headers = new Headers({ authorization: `Bearer ${token}` });
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.id).toBe("user-minimal");
			expect(result!.app_metadata).toEqual({});
			expect(result!.user_metadata).toEqual({});
		});
	});

	describe("API fallback mode (without jwtSecret)", () => {
		let mockFetch: ReturnType<typeof vi.fn>;

		beforeEach(() => {
			mockFetch = vi.fn();
			vi.stubGlobal("fetch", mockFetch);
		});

		afterEach(() => {
			vi.unstubAllGlobals();
		});

		const provider = supabaseAuth({
			url: TEST_URL,
			anonKey: TEST_ANON_KEY,
		});

		it("should return null when Authorization header is missing", async () => {
			const headers = new Headers();
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
			expect(mockFetch).not.toHaveBeenCalled();
		});

		it("should call Supabase API with correct headers", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: async () => ({
					id: "user-from-api",
					email: "api@example.com",
					role: "authenticated",
					app_metadata: {},
					user_metadata: {},
				}),
			});

			const headers = new Headers({ authorization: "Bearer some-token" });
			await provider.resolve(headers);

			expect(mockFetch).toHaveBeenCalledWith(`${TEST_URL}/auth/v1/user`, {
				headers: {
					Authorization: "Bearer some-token",
					apikey: TEST_ANON_KEY,
				},
			});
		});

		it("should return null on non-200 response", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: false,
				status: 401,
			});

			const headers = new Headers({ authorization: "Bearer invalid-token" });
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return user on successful response", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: async () => ({
					id: "user-api-123",
					email: "success@example.com",
					role: "authenticated",
					app_metadata: { provider: "email" },
					user_metadata: { name: "API User" },
				}),
			});

			const headers = new Headers({ authorization: "Bearer valid-token" });
			const result = await provider.resolve(headers);
			expect(result).not.toBeNull();
			expect(result!.id).toBe("user-api-123");
			expect(result!.email).toBe("success@example.com");
			expect(result!.role).toBe("authenticated");
			expect(result!.app_metadata).toEqual({ provider: "email" });
			expect(result!.user_metadata).toEqual({ name: "API User" });
		});

		it("should return null when API returns invalid user data (missing id)", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: async () => ({
					email: "noid@example.com",
					role: "authenticated",
				}),
			});

			const headers = new Headers({ authorization: "Bearer some-token" });
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should return null on network error", async () => {
			mockFetch.mockRejectedValueOnce(new Error("Network error"));

			const headers = new Headers({ authorization: "Bearer some-token" });
			const result = await provider.resolve(headers);
			expect(result).toBeNull();
		});

		it("should strip trailing slashes from the URL", async () => {
			const providerWithTrailingSlash = supabaseAuth({
				url: "https://myproject.supabase.co///",
				anonKey: TEST_ANON_KEY,
			});

			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: async () => ({
					id: "user-slash",
					email: "slash@example.com",
					app_metadata: {},
					user_metadata: {},
				}),
			});

			const headers = new Headers({ authorization: "Bearer some-token" });
			await providerWithTrailingSlash.resolve(headers);

			expect(mockFetch).toHaveBeenCalledWith(
				"https://myproject.supabase.co/auth/v1/user",
				expect.any(Object),
			);
		});
	});
});
