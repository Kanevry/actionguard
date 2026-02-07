import type { AuthProvider } from "../types";

export function customAuth<TUser>(
	resolver: (headers: Headers) => Promise<TUser | null>,
): AuthProvider<TUser> {
	return {
		resolve: resolver,
	};
}
