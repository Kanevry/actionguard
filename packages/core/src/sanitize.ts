export interface SanitizeConfig {
	/** Fields to skip sanitization for */
	skipFields?: string[];
	/** Whether to sanitize deeply (nested objects/arrays). Default: true */
	deep?: boolean;
}

const HTML_ENTITY_MAP: Record<string, string> = {
	"&": "&amp;",
	"<": "&lt;",
	">": "&gt;",
	'"': "&quot;",
	"'": "&#x27;",
	"`": "&#x60;",
};

const HTML_ESCAPE_REGEX = /[&<>"'`]/g;

/** Escape HTML entities in a string to prevent XSS */
export function escapeHtml(str: string): string {
	return str.replace(HTML_ESCAPE_REGEX, (char) => HTML_ENTITY_MAP[char]);
}

/** Sanitize a single value (string -> escaped, others pass through unchanged) */
export function sanitizeValue(value: unknown): unknown {
	if (typeof value === "string") {
		return escapeHtml(value);
	}

	if (value === null || value === undefined) {
		return value;
	}

	if (typeof value === "number" || typeof value === "boolean") {
		return value;
	}

	if (Array.isArray(value)) {
		return value.map((item) => sanitizeValue(item));
	}

	if (typeof value === "object") {
		return sanitizeObject(value as Record<string, unknown>);
	}

	return value;
}

function sanitizeObject(obj: Record<string, unknown>): Record<string, unknown> {
	const result: Record<string, unknown> = {};
	for (const key of Object.keys(obj)) {
		result[key] = sanitizeValue(obj[key]);
	}
	return result;
}

function sanitizeDeep(value: unknown, config: SanitizeConfig, currentKey?: string): unknown {
	const skipFields = config.skipFields ?? [];

	if (currentKey !== undefined && skipFields.includes(currentKey)) {
		return value;
	}

	if (typeof value === "string") {
		return escapeHtml(value);
	}

	if (value === null || value === undefined) {
		return value;
	}

	if (typeof value === "number" || typeof value === "boolean") {
		return value;
	}

	if (Array.isArray(value)) {
		return value.map((item) => sanitizeDeep(item, config));
	}

	if (typeof value === "object") {
		const obj = value as Record<string, unknown>;
		const result: Record<string, unknown> = {};
		for (const key of Object.keys(obj)) {
			result[key] = sanitizeDeep(obj[key], config, key);
		}
		return result;
	}

	return value;
}

/** Deep sanitize an object/input, respecting config */
export function sanitizeInput<T>(input: T, config?: SanitizeConfig): T {
	const resolvedConfig: SanitizeConfig = {
		skipFields: config?.skipFields ?? [],
		deep: config?.deep ?? true,
	};

	if (input === null || input === undefined) {
		return input;
	}

	if (typeof input === "string") {
		return escapeHtml(input) as T;
	}

	if (typeof input === "number" || typeof input === "boolean") {
		return input;
	}

	if (!resolvedConfig.deep) {
		if (Array.isArray(input)) {
			return input.map((item) => {
				if (typeof item === "string") {
					return escapeHtml(item);
				}
				return item;
			}) as T;
		}

		if (typeof input === "object") {
			const obj = input as Record<string, unknown>;
			const result: Record<string, unknown> = {};
			const skipFields = resolvedConfig.skipFields ?? [];
			for (const key of Object.keys(obj)) {
				if (skipFields.includes(key)) {
					result[key] = obj[key];
				} else if (typeof obj[key] === "string") {
					result[key] = escapeHtml(obj[key] as string);
				} else {
					result[key] = obj[key];
				}
			}
			return result as T;
		}

		return input;
	}

	if (Array.isArray(input)) {
		return input.map((item) => sanitizeDeep(item, resolvedConfig)) as T;
	}

	if (typeof input === "object") {
		const obj = input as Record<string, unknown>;
		const result: Record<string, unknown> = {};
		const skipFields = resolvedConfig.skipFields ?? [];
		for (const key of Object.keys(obj)) {
			if (skipFields.includes(key)) {
				result[key] = obj[key];
			} else {
				result[key] = sanitizeDeep(obj[key], resolvedConfig, key);
			}
		}
		return result as T;
	}

	return input;
}
