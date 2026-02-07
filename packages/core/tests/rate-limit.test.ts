import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRateLimiter, MemoryRateLimitStore, parseWindow } from "../src/rate-limit";

// ---------------------------------------------------------------------------
// parseWindow
// ---------------------------------------------------------------------------
describe("parseWindow", () => {
	describe("valid inputs", () => {
		it("should parse seconds ('30s')", () => {
			expect(parseWindow("30s")).toBe(30_000);
		});

		it("should parse one minute ('1m')", () => {
			expect(parseWindow("1m")).toBe(60_000);
		});

		it("should parse five minutes ('5m')", () => {
			expect(parseWindow("5m")).toBe(300_000);
		});

		it("should parse one hour ('1h')", () => {
			expect(parseWindow("1h")).toBe(3_600_000);
		});

		it("should parse one day ('1d')", () => {
			expect(parseWindow("1d")).toBe(86_400_000);
		});

		it("should handle uppercase unit letters", () => {
			expect(parseWindow("10S")).toBe(10_000);
			expect(parseWindow("2M")).toBe(120_000);
			expect(parseWindow("3H")).toBe(10_800_000);
			expect(parseWindow("2D")).toBe(172_800_000);
		});

		it("should handle leading/trailing whitespace", () => {
			expect(parseWindow("  5m  ")).toBe(300_000);
		});

		it("should handle whitespace between number and unit", () => {
			expect(parseWindow("10 s")).toBe(10_000);
		});
	});

	describe("invalid inputs", () => {
		it("should throw for an empty string", () => {
			expect(() => parseWindow("")).toThrow(/Invalid window format/);
		});

		it("should throw for alphabetic-only input ('abc')", () => {
			expect(() => parseWindow("abc")).toThrow(/Invalid window format/);
		});

		it("should throw for zero value ('0s')", () => {
			expect(() => parseWindow("0s")).toThrow(/positive integer/);
		});

		it("should throw for negative value ('-1m')", () => {
			expect(() => parseWindow("-1m")).toThrow(/Invalid window format/);
		});

		it("should throw for unknown unit ('1x')", () => {
			expect(() => parseWindow("1x")).toThrow(/Invalid window format/);
		});

		it("should throw for a plain number without unit", () => {
			expect(() => parseWindow("100")).toThrow(/Invalid window format/);
		});
	});
});

// ---------------------------------------------------------------------------
// MemoryRateLimitStore
// ---------------------------------------------------------------------------
describe("MemoryRateLimitStore", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("should allow requests within the limit", async () => {
		const store = new MemoryRateLimitStore();
		const windowMs = 60_000;
		const maxRequests = 3;

		const r1 = await store.check("key", maxRequests, windowMs);
		expect(r1.allowed).toBe(true);
		expect(r1.remaining).toBe(2);

		const r2 = await store.check("key", maxRequests, windowMs);
		expect(r2.allowed).toBe(true);
		expect(r2.remaining).toBe(1);

		const r3 = await store.check("key", maxRequests, windowMs);
		expect(r3.allowed).toBe(true);
		expect(r3.remaining).toBe(0);
	});

	it("should deny requests exceeding the limit", async () => {
		const store = new MemoryRateLimitStore();
		const windowMs = 60_000;
		const maxRequests = 2;

		await store.check("key", maxRequests, windowMs);
		await store.check("key", maxRequests, windowMs);

		const result = await store.check("key", maxRequests, windowMs);
		expect(result.allowed).toBe(false);
		expect(result.remaining).toBe(0);
	});

	it("should expire old entries after the window passes (sliding window)", async () => {
		const store = new MemoryRateLimitStore();
		const windowMs = 10_000; // 10s
		const maxRequests = 2;

		// Use up the limit
		await store.check("key", maxRequests, windowMs);
		await store.check("key", maxRequests, windowMs);

		const blocked = await store.check("key", maxRequests, windowMs);
		expect(blocked.allowed).toBe(false);

		// Advance time past the window so all entries expire
		vi.advanceTimersByTime(11_000);

		const afterExpiry = await store.check("key", maxRequests, windowMs);
		expect(afterExpiry.allowed).toBe(true);
		expect(afterExpiry.remaining).toBe(1);
	});

	it("should slide the window so only the oldest entries expire", async () => {
		const store = new MemoryRateLimitStore();
		const windowMs = 10_000;
		const maxRequests = 2;

		// First request at t=0
		await store.check("key", maxRequests, windowMs);

		// Second request at t=5s
		vi.advanceTimersByTime(5_000);
		await store.check("key", maxRequests, windowMs);

		// Blocked at t=5s
		const blocked = await store.check("key", maxRequests, windowMs);
		expect(blocked.allowed).toBe(false);

		// Advance to t=11s: first request (t=0) is now older than 10s window
		vi.advanceTimersByTime(6_000);

		const afterPartialExpiry = await store.check("key", maxRequests, windowMs);
		expect(afterPartialExpiry.allowed).toBe(true);
		// One entry remains (t=5s is still within window at t=11s), plus the new one
		expect(afterPartialExpiry.remaining).toBe(0);
	});

	it("should reset state for a key", async () => {
		const store = new MemoryRateLimitStore();
		const windowMs = 60_000;
		const maxRequests = 1;

		await store.check("key", maxRequests, windowMs);

		const blocked = await store.check("key", maxRequests, windowMs);
		expect(blocked.allowed).toBe(false);

		await store.reset("key");

		const afterReset = await store.check("key", maxRequests, windowMs);
		expect(afterReset.allowed).toBe(true);
		expect(afterReset.remaining).toBe(0);
	});

	it("should track keys independently", async () => {
		const store = new MemoryRateLimitStore();
		const windowMs = 60_000;
		const maxRequests = 1;

		await store.check("key-a", maxRequests, windowMs);
		const blockedA = await store.check("key-a", maxRequests, windowMs);
		expect(blockedA.allowed).toBe(false);

		// key-b should still be available
		const resultB = await store.check("key-b", maxRequests, windowMs);
		expect(resultB.allowed).toBe(true);
	});

	it("should return a resetAt date in the future", async () => {
		const store = new MemoryRateLimitStore();
		const now = Date.now();
		const windowMs = 60_000;

		const result = await store.check("key", 5, windowMs);
		expect(result.resetAt.getTime()).toBeGreaterThanOrEqual(now);
		expect(result.resetAt.getTime()).toBeLessThanOrEqual(now + windowMs + 1);
	});
});

// ---------------------------------------------------------------------------
// createRateLimiter
// ---------------------------------------------------------------------------
describe("createRateLimiter", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("should create a limiter that enforces limits", async () => {
		const limiter = createRateLimiter({ maxRequests: 2, window: "1m" });

		const r1 = await limiter();
		expect(r1.allowed).toBe(true);
		expect(r1.remaining).toBe(1);

		const r2 = await limiter();
		expect(r2.allowed).toBe(true);
		expect(r2.remaining).toBe(0);

		const r3 = await limiter();
		expect(r3.allowed).toBe(false);
		expect(r3.remaining).toBe(0);
	});

	it("should use the default 'global' key when no keyFn is provided", async () => {
		const limiter = createRateLimiter({ maxRequests: 1, window: "1m" });

		await limiter();
		// Second call with no arguments should hit the same "global" key
		const result = await limiter();
		expect(result.allowed).toBe(false);
	});

	it("should support a custom keyFn for per-user rate limiting", async () => {
		const limiter = createRateLimiter({
			maxRequests: 1,
			window: "1m",
			keyFn: (userId: unknown) => `user:${userId}`,
		});

		const r1 = await limiter("alice");
		expect(r1.allowed).toBe(true);

		// alice is blocked
		const r2 = await limiter("alice");
		expect(r2.allowed).toBe(false);

		// bob still has quota
		const r3 = await limiter("bob");
		expect(r3.allowed).toBe(true);
	});

	it("should reset via limiter.reset()", async () => {
		const limiter = createRateLimiter({
			maxRequests: 1,
			window: "1m",
			keyFn: (userId: unknown) => `user:${userId}`,
		});

		await limiter("alice");
		const blocked = await limiter("alice");
		expect(blocked.allowed).toBe(false);

		await limiter.reset("alice");

		const afterReset = await limiter("alice");
		expect(afterReset.allowed).toBe(true);
	});

	it("should expose the underlying store", () => {
		const limiter = createRateLimiter({ maxRequests: 5, window: "30s" });
		expect(limiter.store).toBeDefined();
		expect(limiter.store).toBeInstanceOf(MemoryRateLimitStore);
	});

	it("should accept a custom store", async () => {
		const customStore = new MemoryRateLimitStore();
		const limiter = createRateLimiter({
			maxRequests: 5,
			window: "30s",
			store: customStore,
		});

		expect(limiter.store).toBe(customStore);

		await limiter();
		// Verify the custom store received the entry by checking via the store
		const directCheck = await customStore.check("global", 100, 30_000);
		// Should show 2 entries (one from limiter, one from this direct check)
		expect(directCheck.remaining).toBe(98);
	});

	it("should throw for an invalid window string", () => {
		expect(() => createRateLimiter({ maxRequests: 5, window: "invalid" })).toThrow(
			/Invalid window format/,
		);
	});

	it("should allow requests again after the window expires", async () => {
		const limiter = createRateLimiter({ maxRequests: 1, window: "10s" });

		await limiter();
		const blocked = await limiter();
		expect(blocked.allowed).toBe(false);

		vi.advanceTimersByTime(11_000);

		const afterExpiry = await limiter();
		expect(afterExpiry.allowed).toBe(true);
	});
});
