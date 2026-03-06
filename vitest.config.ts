import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
			"test/spec/**/*.test.ts",
		],
    exclude: [
			"**/node_modules/**",
			"**/docs/**",
			"**/dist/**",
		],
    globals: false,
    testTimeout: 600000, // 10 minutes — Monte Carlo: 400 × 10000 iterations
    hookTimeout: 30000,
    pool: "threads",
    poolOptions: {
      threads: {
        maxThreads: 1, // sequential — Monte Carlo tests are CPU-heavy
        minThreads: 1,
      },
    },
    sequence: {
      concurrent: false, // run test files one at a time
    },
  },
});
