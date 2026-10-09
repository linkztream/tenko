// The Playwright fixtures of the end-to-end tests. Every test gets its own `tenko serve`
// (fresh data directory, free port), so scenarios never share state and run in parallel.
//
// - `transport`: the option a spec sets with `test.use({ transport: "internal_ca" })`;
//   `plain` (Lab profile, http://localhost) by default.
// - `server`: the running server, set up by nobody yet; its log is attached to a failing
//   test.
// - `baseURL`: the server's origin, so `page.goto("/ipam")` works.
// - `api`: the API over the page's request context (shares the browser's cookies).
// - `signedIn`: first-run setup done through the API with the server's bootstrap profile;
//   the browser is signed in as the administrator and shows the dashboard.

import { test as base, expect } from "@playwright/test";
import { Api, type SessionInfo } from "./api";
import { TenkoServer, type Transport } from "./server";

export interface Options {
  transport: Transport;
}

export interface SignedIn {
  session: SessionInfo;
}

export interface Fixtures {
  server: TenkoServer;
  api: Api;
  signedIn: SignedIn;
}

export const test = base.extend<Options & Fixtures>({
  transport: ["plain", { option: true }],

  server: async ({ transport }, use, testInfo) => {
    const server = await TenkoServer.start({ transport });
    try {
      await use(server);
    } finally {
      if (testInfo.status !== testInfo.expectedStatus) {
        await testInfo.attach("tenko-serve.log", { body: server.output(), contentType: "text/plain" });
      }
      await server.stop();
    }
  },

  baseURL: async ({ server }, use) => {
    await use(server.url);
  },

  api: async ({ page, server }, use) => {
    await use(new Api(page.request, server.url));
  },

  signedIn: async ({ server, api, page }, use) => {
    const session = await api.setup(server.setupToken, server.profile);
    await page.goto("/");
    await expect(page.getByTestId("page-dashboard")).toBeVisible();
    await use({ session });
  },
});

export { expect };
