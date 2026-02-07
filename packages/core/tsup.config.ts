import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts", "src/auth/supabase.ts", "src/auth/next-auth.ts", "src/auth/custom.ts"],
	format: ["cjs", "esm"],
	dts: true,
	splitting: true,
	sourcemap: true,
	clean: true,
	treeshake: true,
});
