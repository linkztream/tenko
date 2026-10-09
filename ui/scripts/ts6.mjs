// @ts-check
// Preload for Node tools that need the TypeScript compiler API (ESLint with
// typescript-eslint, openapi-typescript). The project compiles with TypeScript 7, whose
// `typescript` package ships the native compiler without the JavaScript API, so these
// tools resolve `typescript` to the TypeScript 6 API package instead.
//
// Usage: node --import ./scripts/ts6.mjs <tool entry point> [arguments]
import { registerHooks } from "node:module";

const TS6 = import.meta.resolve("@typescript/typescript6");

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "typescript") {
      return { url: TS6, shortCircuit: true, format: "commonjs" };
    }
    return nextResolve(specifier, context);
  },
});
