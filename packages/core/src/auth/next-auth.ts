import { createHmac, timingSafeEqual } from "node:crypto";
import type { AuthProvider } from "../types";

export interface NextAuthConfig {
	/** NEXTAUTH_SECRET for JWT verification */
	secret?: string;
	/** Cookie name override. Defaults to auto-detect based on secure flag */
	cookieName?: string;
	/** Whether the app runs on HTTPS (affects cookie name). Default: true in production */
	secure?: boolean;
	/** Fallback: URL to fetch session from (e.g., http://localhost:3000/api/auth/session) */
	sessionEndpoint?: string;
}

export interface NextAuthUser {
	id?: string;
	name?: string | null;
	email?: string | null;
	image?: string | null;
	[key: string]: unknown;
}

/**
 * Create a NextAuth/Auth.js authentication provider.
 *
 * Supports two modes:
 * - **Mode A (JWT):** Verifies the session-token JWT locally using the provided secret (HS256).
 *   Zero network calls. Requires `secret` in config.
 * - **Mode B (Session endpoint):** Fetches the session from a NextAuth API endpoint by
 *   forwarding cookies. Requires `sessionEndpoint` in config.
 *
 * If both `secret` and `sessionEndpoint` are provided, JWT verification is attempted first.
 * The session endpoint is used as a fallback if JWT verification fails.
 */
export function nextAuth(config: NextAuthConfig = {}): AuthProvider<NextAuthUser> {
	const { secret, sessionEndpoint } = config;

	if (!secret && !sessionEndpoint) {
		throw new Error(
			"nextAuth requires at least one of `secret` (for JWT verification) " +
				"or `sessionEndpoint` (for session fetching)",
		);
	}

	return {
		async resolve(headers: Headers): Promise<NextAuthUser | null> {
			const token = extractSessionToken(headers, config);
			if (!token) {
				return null;
			}

			// Mode A: JWT verification (preferred, zero network calls)
			if (secret) {
				const user = verifyJwt(token, secret);
				if (user) {
					return user;
				}
				// If JWT verification fails and no fallback, return null
				if (!sessionEndpoint) {
					return null;
				}
			}

			// Mode B: Session endpoint callback (fallback, one network call)
			if (sessionEndpoint) {
				return fetchSession(sessionEndpoint, headers);
			}

			return null;
		},
	};
}

/**
 * Extract the NextAuth session token from the cookie header.
 */
function extractSessionToken(headers: Headers, config: NextAuthConfig): string | null {
	const cookieHeader = headers.get("cookie");
	if (!cookieHeader) {
		return null;
	}

	const cookieName = config.cookieName ?? getDefaultCookieName(config.secure);
	return parseCookieValue(cookieHeader, cookieName);
}

/**
 * Determine the default NextAuth cookie name based on the secure flag.
 *
 * NextAuth uses `__Secure-next-auth.session-token` when running on HTTPS
 * and `next-auth.session-token` for plain HTTP (typically local development).
 */
function getDefaultCookieName(secure?: boolean): string {
	const isSecure =
		secure ?? (typeof process !== "undefined" && process.env.NODE_ENV === "production");
	return isSecure ? "__Secure-next-auth.session-token" : "next-auth.session-token";
}

/**
 * Parse a specific cookie value from a cookie header string.
 */
function parseCookieValue(cookieHeader: string, name: string): string | null {
	const cookies = cookieHeader.split(";");
	for (const cookie of cookies) {
		const [cookieName, ...valueParts] = cookie.trim().split("=");
		if (cookieName?.trim() === name) {
			const value = valueParts.join("=").trim();
			return value || null;
		}
	}
	return null;
}

/**
 * Verify and decode a standard JWT (HS256) using the provided secret.
 *
 * Note: NextAuth by default uses JWE (A256CBC-HS512) for token encryption. This function
 * supports standard HS256 JWTs, which can be produced when users customize NextAuth's
 * `jwt` callback to return standard signed tokens.
 *
 * Returns the decoded user payload or null if verification fails.
 */
function verifyJwt(token: string, secret: string): NextAuthUser | null {
	try {
		const parts = token.split(".");
		if (parts.length !== 3) {
			return null;
		}

		const [headerB64, payloadB64, signatureB64] = parts;

		// Verify the header indicates HS256
		const header = JSON.parse(base64UrlDecode(headerB64));
		if (header.alg !== "HS256") {
			return null;
		}

		// Verify the signature
		const signingInput = `${headerB64}.${payloadB64}`;
		const expectedSignature = createHmac("sha256", secret).update(signingInput).digest();
		const actualSignature = base64UrlDecodeToBuffer(signatureB64);

		if (expectedSignature.length !== actualSignature.length) {
			return null;
		}

		if (!timingSafeEqual(expectedSignature, actualSignature)) {
			return null;
		}

		// Decode the payload
		const payload = JSON.parse(base64UrlDecode(payloadB64));

		// Check expiration
		if (payload.exp && typeof payload.exp === "number") {
			const now = Math.floor(Date.now() / 1000);
			if (now >= payload.exp) {
				return null;
			}
		}

		// Check not-before
		if (payload.nbf && typeof payload.nbf === "number") {
			const now = Math.floor(Date.now() / 1000);
			if (now < payload.nbf) {
				return null;
			}
		}

		// Map JWT claims to NextAuthUser
		return mapPayloadToUser(payload);
	} catch {
		return null;
	}
}

/**
 * Map a JWT payload to a NextAuthUser.
 *
 * NextAuth JWT payloads typically include `sub` (user ID), `name`, `email`, `picture`/`image`.
 * This function normalizes these fields into the NextAuthUser shape.
 */
function mapPayloadToUser(payload: Record<string, unknown>): NextAuthUser {
	const user: NextAuthUser = {};

	// Standard JWT `sub` claim maps to user ID
	if (payload.sub) {
		user.id = String(payload.sub);
	} else if (payload.id) {
		user.id = String(payload.id);
	}

	if (typeof payload.name === "string" || payload.name === null) {
		user.name = payload.name;
	}

	if (typeof payload.email === "string" || payload.email === null) {
		user.email = payload.email;
	}

	// NextAuth uses `picture` in JWT, but the User type uses `image`
	if (typeof payload.image === "string" || payload.image === null) {
		user.image = payload.image;
	} else if (typeof payload.picture === "string" || payload.picture === null) {
		user.image = payload.picture;
	}

	// Carry over any additional claims
	const reservedKeys = new Set([
		"sub",
		"id",
		"name",
		"email",
		"image",
		"picture",
		"iat",
		"exp",
		"nbf",
		"jti",
		"iss",
		"aud",
	]);
	for (const [key, value] of Object.entries(payload)) {
		if (!reservedKeys.has(key)) {
			user[key] = value;
		}
	}

	return user;
}

/**
 * Fetch the session from a NextAuth API endpoint by forwarding the cookie header.
 */
async function fetchSession(endpoint: string, headers: Headers): Promise<NextAuthUser | null> {
	try {
		const cookieHeader = headers.get("cookie");
		if (!cookieHeader) {
			return null;
		}

		const response = await fetch(endpoint, {
			method: "GET",
			headers: {
				cookie: cookieHeader,
			},
		});

		if (!response.ok) {
			return null;
		}

		const session: unknown = await response.json();

		// NextAuth session endpoint returns { user: { ... }, expires: "..." }
		if (
			session &&
			typeof session === "object" &&
			"user" in session &&
			session.user &&
			typeof session.user === "object"
		) {
			return session.user as NextAuthUser;
		}

		return null;
	} catch {
		return null;
	}
}

/**
 * Decode a base64url-encoded string to a UTF-8 string.
 */
function base64UrlDecode(input: string): string {
	return Buffer.from(base64UrlToBase64(input), "base64").toString("utf-8");
}

/**
 * Decode a base64url-encoded string to a Buffer.
 */
function base64UrlDecodeToBuffer(input: string): Buffer {
	return Buffer.from(base64UrlToBase64(input), "base64");
}

/**
 * Convert base64url encoding to standard base64.
 */
function base64UrlToBase64(input: string): string {
	let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
	const remainder = base64.length % 4;
	if (remainder === 2) {
		base64 += "==";
	} else if (remainder === 3) {
		base64 += "=";
	}
	return base64;
}
