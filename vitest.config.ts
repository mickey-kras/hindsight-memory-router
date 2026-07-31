import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts"],
      reporter: ["text", "lcov", "json-summary"],
      reportOnFailure: true,
      thresholds: {
        lines: 90,
        branches: 85,
      },
    },
  },
});
