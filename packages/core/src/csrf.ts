import { randomUUID } from "node:crypto";

export interface CsrfValidationConfig {
	cookieName?: string;
	headerName?: string;
}

const DEFAULTS = {
	cookieName: "actionguard-csrf",
	headerName: "x-actionguard-csrf",
} as const satisfies Required<CsrfValidationConfig>;

/**
 * Generate a cryptographically random CSRF token using crypto.randomUUID().
 */
export function generateCsrfToken(): string {
	return randomUUID();
}

/**
 * Extract the CSRF token from the request header.
 */
export function getCsrfTokenFromHeaders(
	headers: Headers,
	config?: CsrfValidationConfig,
): string | null {
	const headerName = config?.headerName ?? DEFAULTS.headerName;
	const value = headers.get(headerName);
	if (value === null || value.trim() === "") {
		return null;
	}
	return value.trim();
}

/**
 * Parse the Cookie header and extract the CSRF token value.
 */
export function getCsrfTokenFromCookie(
	headers: Headers,
	config?: CsrfValidationConfig,
): string | null {
	const cookieName = config?.cookieName ?? DEFAULTS.cookieName;
	const cookieHeader = headers.get("cookie");
	if (cookieHeader === null || cookieHeader.trim() === "") {
		return null;
	}

	const cookies = cookieHeader.split(";");
	for (const cookie of cookies) {
		const equalsIndex = cookie.indexOf("=");
		if (equalsIndex === -1) {
			continue;
		}
		const name = cookie.slice(0, equalsIndex).trim();
		const value = cookie.slice(equalsIndex + 1).trim();
		if (name === cookieName) {
			return value === "" ? null : value;
		}
	}

	return null;
}

/**
 * Validate the double-submit cookie CSRF pattern.
 * Compares the token sent via the request header against the token in the cookie.
 * Both must be present and must match exactly.
 */
export function validateCsrf(
	headers: Headers,
	config?: CsrfValidationConfig,
): { valid: boolean; error?: string } {
	const headerToken = getCsrfTokenFromHeaders(headers, config);
	if (headerToken === null) {
		const headerName = config?.headerName ?? DEFAULTS.headerName;
		return {
			valid: false,
			error: `Missing CSRF token in header "${headerName}"`,
		};
	}

	const cookieToken = getCsrfTokenFromCookie(headers, config);
	if (cookieToken === null) {
		const cookieName = config?.cookieName ?? DEFAULTS.cookieName;
		return {
			valid: false,
			error: `Missing CSRF token in cookie "${cookieName}"`,
		};
	}

	if (headerToken !== cookieToken) {
		return {
			valid: false,
			error: "CSRF token mismatch: header token does not match cookie token",
		};
	}

	return { valid: true };
}

/**
 * Build a Set-Cookie header value for the CSRF token.
 * Uses SameSite=Strict, HttpOnly=false (client JS must read it), Secure, and Path=/.
 */
export function buildCsrfCookieHeader(
	token: string,
	config?: CsrfValidationConfig & { secure?: boolean; path?: string; maxAge?: number },
): string {
	const cookieName = config?.cookieName ?? DEFAULTS.cookieName;
	const secure = config?.secure ?? true;
	const path = config?.path ?? "/";
	const maxAge = config?.maxAge ?? 86400;

	const parts = [`${cookieName}=${token}`, `Path=${path}`, "SameSite=Strict", `Max-Age=${maxAge}`];

	if (secure) {
		parts.push("Secure");
	}

	return parts.join("; ");
}
