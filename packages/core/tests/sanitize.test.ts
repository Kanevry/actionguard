import { describe, expect, it } from "vitest";
import { escapeHtml, sanitizeInput, sanitizeValue } from "../src/sanitize";

describe("escapeHtml", () => {
	it("should escape ampersand", () => {
		expect(escapeHtml("foo & bar")).toBe("foo &amp; bar");
	});

	it("should escape less-than", () => {
		expect(escapeHtml("a < b")).toBe("a &lt; b");
	});

	it("should escape greater-than", () => {
		expect(escapeHtml("a > b")).toBe("a &gt; b");
	});

	it("should escape double quotes", () => {
		expect(escapeHtml('say "hello"')).toBe("say &quot;hello&quot;");
	});

	it("should escape single quotes", () => {
		expect(escapeHtml("it's")).toBe("it&#x27;s");
	});

	it("should escape backticks", () => {
		expect(escapeHtml("use `code`")).toBe("use &#x60;code&#x60;");
	});

	it("should escape multiple different characters in one string", () => {
		expect(escapeHtml('<script>alert("xss")</script>')).toBe(
			"&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;",
		);
	});

	it("should pass through safe strings unchanged", () => {
		expect(escapeHtml("hello world")).toBe("hello world");
		expect(escapeHtml("")).toBe("");
		expect(escapeHtml("abc123")).toBe("abc123");
		expect(escapeHtml("no special chars here")).toBe("no special chars here");
	});
});

describe("sanitizeValue", () => {
	it("should escape strings", () => {
		expect(sanitizeValue("<b>bold</b>")).toBe("&lt;b&gt;bold&lt;/b&gt;");
	});

	it("should pass through safe strings", () => {
		expect(sanitizeValue("hello")).toBe("hello");
	});

	it("should pass through numbers", () => {
		expect(sanitizeValue(42)).toBe(42);
		expect(sanitizeValue(0)).toBe(0);
		expect(sanitizeValue(-3.14)).toBe(-3.14);
		expect(sanitizeValue(Number.NaN)).toBeNaN();
	});

	it("should pass through booleans", () => {
		expect(sanitizeValue(true)).toBe(true);
		expect(sanitizeValue(false)).toBe(false);
	});

	it("should pass through null", () => {
		expect(sanitizeValue(null)).toBeNull();
	});

	it("should pass through undefined", () => {
		expect(sanitizeValue(undefined)).toBeUndefined();
	});

	it("should recursively sanitize arrays", () => {
		const input = ["<a>", "safe", 42, null];
		const result = sanitizeValue(input);
		expect(result).toEqual(["&lt;a&gt;", "safe", 42, null]);
	});

	it("should recursively sanitize nested arrays", () => {
		const input = [
			["<b>", "ok"],
			[1, true],
		];
		const result = sanitizeValue(input);
		expect(result).toEqual([
			["&lt;b&gt;", "ok"],
			[1, true],
		]);
	});

	it("should recursively sanitize objects", () => {
		const input = { name: "<script>", count: 5, active: true };
		const result = sanitizeValue(input);
		expect(result).toEqual({ name: "&lt;script&gt;", count: 5, active: true });
	});

	it("should recursively sanitize nested objects", () => {
		const input = { outer: { inner: '<img src="x">' } };
		const result = sanitizeValue(input);
		expect(result).toEqual({ outer: { inner: "&lt;img src=&quot;x&quot;&gt;" } });
	});
});

describe("sanitizeInput", () => {
	describe("deep mode (default)", () => {
		it("should sanitize nested objects", () => {
			const input = {
				user: {
					name: "<script>alert('xss')</script>",
					bio: "I'm a <b>developer</b>",
				},
				count: 10,
			};
			const result = sanitizeInput(input);
			expect(result).toEqual({
				user: {
					name: "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;",
					bio: "I&#x27;m a &lt;b&gt;developer&lt;/b&gt;",
				},
				count: 10,
			});
		});

		it("should sanitize nested arrays", () => {
			const input = {
				tags: ["<b>bold</b>", "safe", "<script>"],
			};
			const result = sanitizeInput(input);
			expect(result).toEqual({
				tags: ["&lt;b&gt;bold&lt;/b&gt;", "safe", "&lt;script&gt;"],
			});
		});

		it("should sanitize deeply nested structures", () => {
			const input = {
				level1: {
					level2: {
						level3: '<img onerror="hack()">',
					},
				},
			};
			const result = sanitizeInput(input);
			expect(result).toEqual({
				level1: {
					level2: {
						level3: "&lt;img onerror=&quot;hack()&quot;&gt;",
					},
				},
			});
		});

		it("should respect skipFields", () => {
			const input = {
				name: "<b>User</b>",
				html: "<div>Keep this</div>",
				description: "<p>Sanitize this</p>",
			};
			const result = sanitizeInput(input, { skipFields: ["html"] });
			expect(result).toEqual({
				name: "&lt;b&gt;User&lt;/b&gt;",
				html: "<div>Keep this</div>",
				description: "&lt;p&gt;Sanitize this&lt;/p&gt;",
			});
		});

		it("should respect multiple skipFields", () => {
			const input = {
				title: "<h1>Title</h1>",
				body: "<p>Body</p>",
				footer: "<footer>Footer</footer>",
			};
			const result = sanitizeInput(input, { skipFields: ["body", "footer"] });
			expect(result).toEqual({
				title: "&lt;h1&gt;Title&lt;/h1&gt;",
				body: "<p>Body</p>",
				footer: "<footer>Footer</footer>",
			});
		});

		it("should handle skipFields on nested object keys", () => {
			const input = {
				outer: {
					content: "<div>Raw HTML</div>",
					name: "<b>Name</b>",
				},
			};
			const result = sanitizeInput(input, { skipFields: ["content"] });
			expect(result).toEqual({
				outer: {
					content: "<div>Raw HTML</div>",
					name: "&lt;b&gt;Name&lt;/b&gt;",
				},
			});
		});
	});

	describe("shallow mode", () => {
		it("should only sanitize top-level strings", () => {
			const input = {
				name: "<b>User</b>",
				nested: {
					html: "<div>Not sanitized</div>",
				},
			};
			const result = sanitizeInput(input, { deep: false });
			expect(result).toEqual({
				name: "&lt;b&gt;User&lt;/b&gt;",
				nested: {
					html: "<div>Not sanitized</div>",
				},
			});
		});

		it("should sanitize top-level strings in arrays", () => {
			const input = ["<a>link</a>", "safe"];
			const result = sanitizeInput(input, { deep: false });
			expect(result).toEqual(["&lt;a&gt;link&lt;/a&gt;", "safe"]);
		});

		it("should not sanitize non-string items in shallow arrays", () => {
			const input = ["<b>bold</b>", 42, { html: "<p>test</p>" }];
			const result = sanitizeInput(input, { deep: false });
			expect(result).toEqual(["&lt;b&gt;bold&lt;/b&gt;", 42, { html: "<p>test</p>" }]);
		});

		it("should respect skipFields in shallow mode", () => {
			const input = {
				name: "<b>User</b>",
				raw: "<div>Keep this</div>",
			};
			const result = sanitizeInput(input, { deep: false, skipFields: ["raw"] });
			expect(result).toEqual({
				name: "&lt;b&gt;User&lt;/b&gt;",
				raw: "<div>Keep this</div>",
			});
		});
	});

	describe("null/undefined/primitive inputs", () => {
		it("should handle null input", () => {
			expect(sanitizeInput(null)).toBeNull();
		});

		it("should handle undefined input", () => {
			expect(sanitizeInput(undefined)).toBeUndefined();
		});

		it("should handle string input", () => {
			expect(sanitizeInput("<b>test</b>")).toBe("&lt;b&gt;test&lt;/b&gt;");
		});

		it("should handle safe string input", () => {
			expect(sanitizeInput("hello")).toBe("hello");
		});

		it("should handle number input", () => {
			expect(sanitizeInput(42)).toBe(42);
		});

		it("should handle boolean input", () => {
			expect(sanitizeInput(true)).toBe(true);
			expect(sanitizeInput(false)).toBe(false);
		});
	});
});
