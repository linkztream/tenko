// Helpers of the tests of this folder: an administrator session from the mock API.
import { api } from "../api/client";
import { resetMockDb, type MockScenario } from "../api/mock/db";
import { setSessionForTest } from "../auth/session";

/** Starts the mock in `scenario` (a signed-in one) and takes over its session as the UI's own. */
export async function signInAs(scenario: MockScenario = "signed-in"): Promise<void> {
  resetMockDb(scenario);
  setSessionForTest(await api.get("/api/v1/auth/session"));
}

/** The route of the settings views, as registered in routes.ts. */
export const SETTINGS_PATH = "/settings/:section?/:id?";
