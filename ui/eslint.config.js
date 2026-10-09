// @ts-check
// Lint of the Tenko DDI UI. Run through `npm run lint`, which preloads scripts/ts6.mjs:
// typescript-eslint needs the TypeScript compiler API, which the TypeScript 7 package no
// longer has.
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import solid from "eslint-plugin-solid/configs/typescript";
import tseslint from "typescript-eslint";
import tenko from "./scripts/eslint/plugin.mjs";

/** Direct network access outside the API layer bypasses the typed client (API-02). */
const NETWORK_OUTSIDE_API = [
  { selector: "CallExpression[callee.name='fetch']", message: "Use api.* from src/api/client.ts." },
  { selector: "NewExpression[callee.name='EventSource']", message: "Subscribe through src/api/events.ts." },
  { selector: "NewExpression[callee.name='XMLHttpRequest']", message: "Use api.* from src/api/client.ts." },
  {
    selector: "ImportSpecifier[imported.name='rawRequest']",
    message: "rawRequest bypasses the typed paths; use api.* with a path from the OpenAPI document.",
  },
];

export default defineConfig(
  { ignores: ["dist/**", "node_modules/**", "public/**", "src/api/generated/**", "src/i18n/generated/**"] },
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    ...solid,
    plugins: { ...solid.plugins, tenko },
    rules: {
      ...solid.rules,
      "tenko/no-literal-ui-string": "error",
      "tenko/no-static-style": "error",
      "no-restricted-syntax": ["error", ...NETWORK_OUTSIDE_API],
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "@typescript-eslint/consistent-type-imports": "error",
      eqeqeq: ["error", "smart"],
      "no-console": ["error", { allow: ["warn", "error"] }],
      // Solid assigns `let el!: HTMLElement` through the `ref` attribute.
      "no-unassigned-vars": "off",
    },
  },
  {
    // The API layer itself, the mock API and tests may talk to the network and use
    // literal sample text.
    files: ["src/api/**/*.{ts,tsx}", "src/**/*.test.{ts,tsx}", "src/app/testing/**"],
    rules: { "no-restricted-syntax": "off" },
  },
  {
    files: ["src/**/*.test.{ts,tsx}", "src/api/mock/**", "src/app/testing/**"],
    rules: { "tenko/no-literal-ui-string": "off" },
  },
  {
    files: ["scripts/**/*.mjs", "*.config.{js,ts}"],
    languageOptions: {
      globals: {
        process: "readonly",
        console: "readonly",
        URL: "readonly",
        Buffer: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        structuredClone: "readonly",
      },
    },
  },
);
