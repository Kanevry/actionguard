export interface RateLimitResult {
	allowed: boolean;
	remaining: number;
	resetAt: Date;
}

export interface RateLimitStore {
	check(key: string, maxRequests: number, windowMs: number): Promise<RateLimitResult>;
	reset(key: string): Promise<void>;
}

export interface RateLimiterOptions {
	/** Maximum number of requests allowed within the window. */
	maxRequests: number;
	/** Time window as a human-readable string, e.g. '30s', '1m', '5m', '1h', '1d'. */
	window: string;
	/** Function that derives a rate-limit key from arbitrary context. Defaults to () => "global". */
	keyFn?: (...args: unknown[]) => string;
	/** Backing store implementation. Defaults to an in-memory sliding window store. */
	store?: RateLimitStore;
}

const UNIT_MS: Record<string, number> = {
	s: 1_000,
	m: 60_000,
	h: 3_600_000,
	d: 86_400_000,
};

/**
 * Parse a human-readable time window string into milliseconds.
 *
 * Supported formats: '30s', '1m', '5m', '1h', '1d'
 *
 * @throws {Error} If the format is invalid or the unit is unrecognised.
 */
export function parseWindow(window: string): number {
	const trimmed = window.trim();
	const match = /^(\d+)\s*([smhd])$/i.exec(trimmed);

	if (!match) {
		throw new Error(
			`Invalid window format "${window}". Expected a number followed by s, m, h, or d (e.g. "30s", "5m", "1h", "1d").`,
		);
	}

	const value = Number.parseInt(match[1], 10);
	const unit = match[2].toLowerCase();
	const multiplier = UNIT_MS[unit];

	if (multiplier === undefined) {
		throw new Error(`Unknown time unit "${unit}".`);
	}

	if (value <= 0) {
		throw new Error(`Window value must be a positive integer, got ${value}.`);
	}

	return value * multiplier;
}

/**
 * In-memory sliding window rate limit store.
 *
 * Keeps a `Map<string, number[]>` where each value is a sorted array of
 * request timestamps (epoch ms). On every `check()` call expired entries
 * outside the current window are pruned before the count is evaluated.
 *
 * This store is suitable for single-process Node.js applications. For
 * multi-process or distributed deployments, supply a Redis-backed store
 * instead.
 */
export class MemoryRateLimitStore implements RateLimitStore {
	private windows = new Map<string, number[]>();

	async check(key: string, maxRequests: number, windowMs: number): Promise<RateLimitResult> {
		const now = Date.now();
		const windowStart = now - windowMs;

		// Retrieve existing timestamps or start fresh.
		let timestamps = this.windows.get(key);

		if (timestamps) {
			// Prune entries that have fallen outside the sliding window.
			timestamps = timestamps.filter((ts) => ts > windowStart);
		} else {
			timestamps = [];
		}

		const allowed = timestamps.length < maxRequests;

		if (allowed) {
			timestamps.push(now);
		}

		// Persist the (possibly pruned) array back into the map.
		this.windows.set(key, timestamps);

		// Determine when the oldest entry in the current window expires,
		// giving the caller a meaningful "retry after" hint.
		const resetAt =
			timestamps.length > 0 ? new Date(timestamps[0] + windowMs) : new Date(now + windowMs);

		return {
			allowed,
			remaining: Math.max(0, maxRequests - timestamps.length),
			resetAt,
		};
	}

	async reset(key: string): Promise<void> {
		this.windows.delete(key);
	}
}

/**
 * Factory that creates a self-contained rate limiter function.
 *
 * ```ts
 * const limiter = createRateLimiter({
 *   maxRequests: 10,
 *   window: "1m",
 *   keyFn: (userId: string) => `user:${userId}`,
 * });
 *
 * const result = await limiter("user-42");
 * if (!result.allowed) {
 *   throw new Error("Rate limit exceeded");
 * }
 * ```
 */
export function createRateLimiter(options: RateLimiterOptions) {
	const { maxRequests, window: windowStr, keyFn, store } = options;

	const windowMs = parseWindow(windowStr);
	const backingStore: RateLimitStore = store ?? new MemoryRateLimitStore();
	const resolveKey = keyFn ?? (() => "global");

	const limiter = async (...args: unknown[]): Promise<RateLimitResult> => {
		const key = resolveKey(...args);
		return backingStore.check(key, maxRequests, windowMs);
	};

	/** Reset the rate limit state for a specific key. */
	limiter.reset = async (...args: unknown[]): Promise<void> => {
		const key = resolveKey(...args);
		return backingStore.reset(key);
	};

	/** The underlying store, exposed for advanced use cases (e.g. testing). */
	limiter.store = backingStore;

	return limiter;
}
