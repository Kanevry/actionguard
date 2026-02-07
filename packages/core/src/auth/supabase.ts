import { createHmac, timingSafeEqual } from "node:crypto";
import type { AuthProvider } from "../types";

export interface SupabaseUser {
	/** Supabase user ID (UUID) */
	id: string;
	/** User email address */
	email?: string;
	/** User role (e.g. "authenticated", "anon") */
	role?: string;
	/** Supabase app metadata (provider, providers, etc.) */
	app_metadata: Record<string, unknown>;
	/** User-defined metadata */
	user_metadata: Record<string, unknown>;
}

export interface SupabaseAuthConfig {
	/** Supabase project URL */
	url: string;
	/** Supabase anon key */
	anonKey: string;
	/** JWT secret for local verification (preferred, avoids network call) */
	jwtSecret?: string;
}

/**
 * Creates a Supabase auth provider for ActionGuard.
 *
 * When `jwtSecret` is provided, the JWT is verified locally using HMAC SHA256
 * (zero network calls). Otherwise, falls back to Supabase's `/auth/v1/user`
 * endpoint to resolve the user from the token.
 */
export function supabaseAuth(config: SupabaseAuthConfig): AuthProvider<SupabaseUser> {
	return {
		async resolve(headers: Headers): Promise<SupabaseUser | null> {
			const token = extractBearerToken(headers);
			if (!token) {
				return null;
			}

			if (config.jwtSecret) {
				return verifyJwtLocally(token, config.jwtSecret);
			}

			return fetchUserFromSupabase(token, config.url, config.anonKey);
		},
	};
}

/**
 * Extract the bearer token from the Authorization header.
 * Returns null if the header is missing or malformed.
 */
function extractBearerToken(headers: Headers): string | null {
	const authorization = headers.get("authorization") ?? headers.get("Authorization");
	if (!authorization) {
		return null;
	}

	const match = authorization.match(/^Bearer\s+(.+)$/i);
	return match?.[1] ?? null;
}

/**
 * Base64url decode a string to a Buffer.
 * Handles the URL-safe alphabet (- instead of +, _ instead of /)
 * and missing padding.
 */
function base64UrlDecode(input: string): Buffer {
	// Replace URL-safe characters with standard Base64 characters
	let base64 = input.replace(/-/g, "+").replace(/_/g, "/");

	// Add padding if necessary
	const paddingNeeded = (4 - (base64.length % 4)) % 4;
	base64 += "=".repeat(paddingNeeded);

	return Buffer.from(base64, "base64");
}

/**
 * Verify a JWT locally using HMAC SHA256.
 * Returns the decoded payload as a SupabaseUser, or null on any failure.
 */
function verifyJwtLocally(token: string, secret: string): SupabaseUser | null {
	const parts = token.split(".");
	if (parts.length !== 3) {
		return null;
	}

	const [headerB64, payloadB64, signatureB64] = parts;

	// Decode and validate header
	let header: { alg?: string; typ?: string };
	try {
		header = JSON.parse(base64UrlDecode(headerB64).toString("utf-8"));
	} catch {
		return null;
	}

	// Only support HS256 (HMAC SHA256) — Supabase's default
	if (header.alg !== "HS256") {
		return null;
	}

	// Verify signature
	const signingInput = `${headerB64}.${payloadB64}`;
	const expectedSignature = createHmac("sha256", secret).update(signingInput).digest();
	const actualSignature = base64UrlDecode(signatureB64);

	// Constant-time comparison to prevent timing attacks
	if (expectedSignature.length !== actualSignature.length) {
		return null;
	}
	if (!timingSafeEqual(expectedSignature, actualSignature)) {
		return null;
	}

	// Decode payload
	let payload: Record<string, unknown>;
	try {
		payload = JSON.parse(base64UrlDecode(payloadB64).toString("utf-8"));
	} catch {
		return null;
	}

	// Check expiration
	if (typeof payload.exp === "number") {
		const nowInSeconds = Math.floor(Date.now() / 1000);
		if (nowInSeconds >= payload.exp) {
			return null;
		}
	}

	// Map JWT claims to SupabaseUser
	return {
		id: (payload.sub as string) ?? "",
		email: payload.email as string | undefined,
		role: payload.role as string | undefined,
		app_metadata: (payload.app_metadata as Record<string, unknown>) ?? {},
		user_metadata: (payload.user_metadata as Record<string, unknown>) ?? {},
	};
}

/**
 * Fallback: fetch the user from Supabase's GoTrue `/auth/v1/user` endpoint.
 * Used when `jwtSecret` is not configured.
 */
async function fetchUserFromSupabase(
	token: string,
	url: string,
	anonKey: string,
): Promise<SupabaseUser | null> {
	// Normalize URL — strip trailing slash
	const baseUrl = url.replace(/\/+$/, "");

	try {
		const response = await fetch(`${baseUrl}/auth/v1/user`, {
			headers: {
				Authorization: `Bearer ${token}`,
				apikey: anonKey,
			},
		});

		if (!response.ok) {
			return null;
		}

		const data = (await response.json()) as Record<string, unknown>;

		// Supabase returns the user object directly from this endpoint
		if (!data.id || typeof data.id !== "string") {
			return null;
		}

		return {
			id: data.id,
			email: data.email as string | undefined,
			role: data.role as string | undefined,
			app_metadata: (data.app_metadata as Record<string, unknown>) ?? {},
			user_metadata: (data.user_metadata as Record<string, unknown>) ?? {},
		};
	} catch {
		// Network error, timeout, etc.
		return null;
	}
}
