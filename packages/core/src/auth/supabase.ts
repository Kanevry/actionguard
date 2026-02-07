import type { AuthProvider } from "../types";

export interface SupabaseAuthConfig {
	url: string;
	anonKey: string;
}

export function supabaseAuth(_config: SupabaseAuthConfig): AuthProvider {
	return {
		async resolve(_headers: Headers) {
			// TODO: Implement Supabase auth resolution
			// This will use @supabase/ssr to resolve the user from cookies
			return null;
		},
	};
}
