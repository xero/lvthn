// @ts-check
import eslint from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig([
  {
    ignores: [
      "**/node_modules/**",
      "**/docs/**",
      "**/dist/**",
      "vitest.config.ts",
      "eslint.config.ts",
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strict,
  ...tseslint.configs.stylistic,
  {
    files: ["src/**/*.ts"],
    rules: {
      // Namespaces are used as an intentional API design pattern in this codebase
      "@typescript-eslint/no-namespace": "off",
    },
  },
  {
    files: ["test/**/*.ts"],
    rules: {
      // Non-null assertions in test files are acceptable — test code asserts known shapes
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  },
  {
    files: ["**/*.ts"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: true,
      },
    },
    rules: {
      indent: ["error", "tab"],
      "no-tabs": "off",
      quotes: ["error", "single"],
      semi: ["error", "always"],
      // comment-format: check-space
      "spaced-comment": ["error", "always"],
      // no-duplicate-variable
      "@typescript-eslint/no-redeclare": "error",
      // no-eval
      "no-eval": "error",
      // no-internal-module
      "@typescript-eslint/prefer-namespace-keyword": "error",
      // no-trailing-whitespace
      "no-trailing-spaces": "error",
      // no-var (was disabled in TSLint, strict enables it — keeping it on)
      "no-var": "error",
      // triple-equals: allow-null-check
      eqeqeq: ["error", "always", { null: "ignore" }],
      // variable-name: ban-keywords
      "id-denylist": [
        "error",
        "any",
        "number",
        "string",
        "boolean",
        "undefined",
        "null",
        "object",
      ],
      // Allow unused vars/args prefixed with _ (conventional pattern for intentionally unused parameters)
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      // whitespace rules
      "keyword-spacing": ["error", { before: true, after: true }],
      "space-before-blocks": "error",
      "space-infix-ops": "error",
      "comma-spacing": ["error", { before: false, after: true }],
      "key-spacing": ["error", { beforeColon: false, afterColon: true }],
      // one-line: check-open-brace
      "brace-style": ["error", "1tbs", { allowSingleLine: false }],
    },
  },
]);
