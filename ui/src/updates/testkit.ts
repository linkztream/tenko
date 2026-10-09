// Helpers of the tests of this folder: an administrator against the mock API, a clean updates
// mock, and a response that makes the update endpoints answer a given problem.
import { http, HttpResponse } from "msw";
import { server } from "../api/mock/node";
import { Problem } from "../api/mock/reply";
import { signInAlex } from "../auth/account/testkit";
import type { MockUser } from "../api/mock/db";
import { resetModules } from "./modules";
import { forgetWhatsNew } from "./WhatsNew";

/** alex, an administrator, signed in; the updates mock is fresh and nothing is remembered. */
export async function signInAdmin(prepare?: (user: MockUser) => void): Promise<void> {
  resetModules();
  forgetWhatsNew();
  await signInAlex(prepare ? { prepare } : {});
}

/** An account that is no administrator. */
export function viewerOnly(user: MockUser): void {
  user.roles = ["viewer"];
}

/** Makes `GET /system/updates` answer with a problem. */
export function updatesFail(status: number, code: string): void {
  server.use(
    http.get("/api/v1/system/updates", () => {
      const reply = new Problem(code, { status }).reply;
      return HttpResponse.json(reply.body, { status, headers: { "content-type": "application/problem+json" } });
    }),
  );
}
