import { cleanup } from "@solidjs/testing-library";
import { afterAll, afterEach, beforeAll } from "vitest";
import { resetMockDb } from "../../api/mock/db";
import { server } from "../../api/mock/node";
import { forgetHosts } from "../../ipam/resolve";

// Every test file talks to the mock API (src/api/mock). A request no handler answers is an
// error, so a test never reaches a real network by accident. (msw 3 names the option
// `onUnhandledFrame`; it was `onUnhandledRequest` before.)
beforeAll(() => {
  server.listen({ onUnhandledFrame: "error" });
});

afterEach(() => {
  cleanup();
  server.resetHandlers();
  resetMockDb();
  // Cached hosts belong to the mock state of the test that read them.
  forgetHosts();
});

afterAll(() => {
  server.close();
});
