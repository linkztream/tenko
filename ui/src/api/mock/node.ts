// The mock API for tests: the same handlers as the browser, without latency.
// `src/app/testing/setup.ts` starts it for every test file.
import { setupServer } from "msw/node";
import { handlers } from "./handlers";

export const server = setupServer(...handlers);
