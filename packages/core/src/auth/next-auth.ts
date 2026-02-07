import type { AuthProvider } from "../types";

export function nextAuth(): AuthProvider {
	return {
		async resolve(_headers: Headers) {
			// TODO: Implement NextAuth/Auth.js resolution
			return null;
		},
	};
}
