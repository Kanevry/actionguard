import { describe, expect, it } from "vitest";
import {
	buildCsrfCookieHeader,
	generateCsrfToken,
	getCsrfTokenFromCookie,
	getCsrfTokenFromHeaders,
	validateCsrf,
} from "../src/csrf";

// ---------------------------------------------------------------------------
// generateCsrfToken
// ---------------------------------------------------------------------------
describe("generateCsrfToken", () => {
	it("should return a string", () => {
		const token = generateCsrfToken();
		expect(typeof token).toBe("string");
		expect(token.length).toBeGreaterThan(0);
	});

	it("should return a different token on each call", () => {
		const tokens = new Set(Array.from({ length: 50 }, () => generateCsrfToken()));
		expect(tokens.size).toBe(50);
	});

	it("should return a UUID-shaped string", () => {
		const token = generateCsrfToken();
		// UUID v4 pattern: 8-4-4-4-12 hex chars
		expect(token).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
	});
});

// ---------------------------------------------------------------------------
// getCsrfTokenFromHeaders
// ---------------------------------------------------------------------------
describe("getCsrfTokenFromHeaders", () => {
	it("should extract the token from the default header", () => {
		const headers = new Headers({ "x-actionguard-csrf": "my-token" });
		expect(getCsrfTokenFromHeaders(headers)).toBe("my-token");
	});

	it("should return null when the header is missing", () => {
		const headers = new Headers();
		expect(getCsrfTokenFromHeaders(headers)).toBeNull();
	});

	it("should return null when the header value is empty", () => {
		const headers = new Headers({ "x-actionguard-csrf": "" });
		expect(getCsrfTokenFromHeaders(headers)).toBeNull();
	});

	it("should return null when the header value is only whitespace", () => {
		const headers = new Headers({ "x-actionguard-csrf": "   " });
		expect(getCsrfTokenFromHeaders(headers)).toBeNull();
	});

	it("should trim the token value", () => {
		const headers = new Headers({ "x-actionguard-csrf": "  trimmed  " });
		expect(getCsrfTokenFromHeaders(headers)).toBe("trimmed");
	});

	it("should use a custom header name from config", () => {
		const headers = new Headers({ "x-custom-csrf": "custom-token" });
		const result = getCsrfTokenFromHeaders(headers, { headerName: "x-custom-csrf" });
		expect(result).toBe("custom-token");
	});

	it("should use the default header name when config has no headerName", () => {
		const headers = new Headers({ "x-actionguard-csrf": "default-token" });
		const result = getCsrfTokenFromHeaders(headers, { cookieName: "other" });
		expect(result).toBe("default-token");
	});
});

// ---------------------------------------------------------------------------
// getCsrfTokenFromCookie
// ---------------------------------------------------------------------------
describe("getCsrfTokenFromCookie", () => {
	it("should extract the token from a simple cookie header", () => {
		const headers = new Headers({ cookie: "actionguard-csrf=token123" });
		expect(getCsrfTokenFromCookie(headers)).toBe("token123");
	});

	it("should return null when no cookie header is present", () => {
		const headers = new Headers();
		expect(getCsrfTokenFromCookie(headers)).toBeNull();
	});

	it("should return null when the cookie header is empty", () => {
		const headers = new Headers({ cookie: "" });
		expect(getCsrfTokenFromCookie(headers)).toBeNull();
	});

	it("should return null when the cookie header is only whitespace", () => {
		const headers = new Headers({ cookie: "   " });
		expect(getCsrfTokenFromCookie(headers)).toBeNull();
	});

	it("should return null when the CSRF cookie is not present among other cookies", () => {
		const headers = new Headers({ cookie: "session=abc; theme=dark" });
		expect(getCsrfTokenFromCookie(headers)).toBeNull();
	});

	it("should handle multiple cookies and extract the correct one", () => {
		const headers = new Headers({
			cookie: "session=abc; actionguard-csrf=my-csrf-token; theme=dark",
		});
		expect(getCsrfTokenFromCookie(headers)).toBe("my-csrf-token");
	});

	it("should use a custom cookie name from config", () => {
		const headers = new Headers({ cookie: "my-csrf=custom-value" });
		const result = getCsrfTokenFromCookie(headers, { cookieName: "my-csrf" });
		expect(result).toBe("custom-value");
	});

	it("should return null when the cookie value is empty", () => {
		const headers = new Headers({ cookie: "actionguard-csrf=" });
		expect(getCsrfTokenFromCookie(headers)).toBeNull();
	});

	it("should handle cookies with spaces around equals sign", () => {
		const headers = new Headers({ cookie: " actionguard-csrf = tok " });
		// The name is trimmed; the value after '=' is trimmed
		expect(getCsrfTokenFromCookie(headers)).toBe("tok");
	});

	it("should handle cookie values containing equals signs", () => {
		const headers = new Headers({ cookie: "actionguard-csrf=abc=def=ghi" });
		// Only splits on first '='
		expect(getCsrfTokenFromCookie(headers)).toBe("abc=def=ghi");
	});
});

// ---------------------------------------------------------------------------
// validateCsrf
// ---------------------------------------------------------------------------
describe("validateCsrf", () => {
	it("should return valid when header and cookie tokens match", () => {
		const token = "matching-token";
		const headers = new Headers({
			"x-actionguard-csrf": token,
			cookie: `actionguard-csrf=${token}`,
		});

		const result = validateCsrf(headers);
		expect(result.valid).toBe(true);
		expect(result.error).toBeUndefined();
	});

	it("should fail when the header token is missing", () => {
		const headers = new Headers({
			cookie: "actionguard-csrf=some-token",
		});

		const result = validateCsrf(headers);
		expect(result.valid).toBe(false);
		expect(result.error).toContain("Missing CSRF token in header");
		expect(result.error).toContain("x-actionguard-csrf");
	});

	it("should fail when the cookie token is missing", () => {
		const headers = new Headers({
			"x-actionguard-csrf": "some-token",
		});

		const result = validateCsrf(headers);
		expect(result.valid).toBe(false);
		expect(result.error).toContain("Missing CSRF token in cookie");
		expect(result.error).toContain("actionguard-csrf");
	});

	it("should fail when header and cookie tokens do not match", () => {
		const headers = new Headers({
			"x-actionguard-csrf": "token-a",
			cookie: "actionguard-csrf=token-b",
		});

		const result = validateCsrf(headers);
		expect(result.valid).toBe(false);
		expect(result.error).toContain("CSRF token mismatch");
	});

	it("should fail when both header and cookie are missing", () => {
		const headers = new Headers();

		const result = validateCsrf(headers);
		expect(result.valid).toBe(false);
		// Header is checked first, so the error should reference the header
		expect(result.error).toContain("Missing CSRF token in header");
	});

	it("should use custom header and cookie names from config", () => {
		const config = { headerName: "x-my-csrf", cookieName: "my-csrf" };
		const token = "custom-token";
		const headers = new Headers({
			"x-my-csrf": token,
			cookie: `my-csrf=${token}`,
		});

		const result = validateCsrf(headers, config);
		expect(result.valid).toBe(true);
	});

	it("should mention the custom header name in the error when it is missing", () => {
		const config = { headerName: "x-custom-header" };
		const headers = new Headers({ cookie: "actionguard-csrf=token" });

		const result = validateCsrf(headers, config);
		expect(result.valid).toBe(false);
		expect(result.error).toContain("x-custom-header");
	});

	it("should mention the custom cookie name in the error when it is missing", () => {
		const config = { cookieName: "custom-cookie" };
		const headers = new Headers({ "x-actionguard-csrf": "token" });

		const result = validateCsrf(headers, config);
		expect(result.valid).toBe(false);
		expect(result.error).toContain("custom-cookie");
	});
});

// ---------------------------------------------------------------------------
// buildCsrfCookieHeader
// ---------------------------------------------------------------------------
describe("buildCsrfCookieHeader", () => {
	it("should include the default cookie name and token", () => {
		const header = buildCsrfCookieHeader("my-token");
		expect(header).toContain("actionguard-csrf=my-token");
	});

	it("should include Path=/", () => {
		const header = buildCsrfCookieHeader("t");
		expect(header).toContain("Path=/");
	});

	it("should include SameSite=Strict", () => {
		const header = buildCsrfCookieHeader("t");
		expect(header).toContain("SameSite=Strict");
	});

	it("should include Max-Age with default value of 86400", () => {
		const header = buildCsrfCookieHeader("t");
		expect(header).toContain("Max-Age=86400");
	});

	it("should include Secure flag by default", () => {
		const header = buildCsrfCookieHeader("t");
		expect(header).toContain("Secure");
	});

	it("should omit Secure flag when secure is false", () => {
		const header = buildCsrfCookieHeader("t", { secure: false });
		expect(header).not.toContain("Secure");
	});

	it("should respect a custom cookie name", () => {
		const header = buildCsrfCookieHeader("tok", { cookieName: "my-csrf" });
		expect(header).toContain("my-csrf=tok");
		expect(header).not.toContain("actionguard-csrf");
	});

	it("should respect a custom path", () => {
		const header = buildCsrfCookieHeader("tok", { path: "/api" });
		expect(header).toContain("Path=/api");
	});

	it("should respect a custom maxAge", () => {
		const header = buildCsrfCookieHeader("tok", { maxAge: 3600 });
		expect(header).toContain("Max-Age=3600");
		expect(header).not.toContain("Max-Age=86400");
	});

	it("should combine all parts with semicolons and spaces", () => {
		const header = buildCsrfCookieHeader("tok");
		const parts = header.split("; ");
		expect(parts.length).toBeGreaterThanOrEqual(4);
		expect(parts[0]).toBe("actionguard-csrf=tok");
	});

	it("should produce a fully custom cookie header", () => {
		const header = buildCsrfCookieHeader("abc123", {
			cookieName: "x-csrf",
			secure: true,
			path: "/app",
			maxAge: 7200,
		});
		expect(header).toBe("x-csrf=abc123; Path=/app; SameSite=Strict; Max-Age=7200; Secure");
	});
});
