// Renders the whole application in a memory router, as the tests of the areas and settings pages
// need it.
import { createMemoryHistory, MemoryRouter } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import { resetMockDb, type MockScenario } from "../../api/mock/db";
import { mockUpdates } from "../../api/mock/routes-updates";
import { buildRoutes, Root } from "../../App";
import { alex } from "../../auth/account/testkit";
import { loadSession, setSessionForTest } from "../../auth/session";

export interface RenderAppOptions {
  /** The state of the mock database (default "signed-in"). */
  scenario?: MockScenario;
  /** The roles of the signed-in account (default: the scenario's). */
  roles?: readonly string[];
  /** The modules the server reports as running and configured (default: the mock's). */
  modules?: readonly string[];
}

/**
 * The whole application at `url`, after the mock database and the session were reset and the
 * session loaded. Returns the testing-library result and the current location.
 */
export async function renderApp(url: string, options: RenderAppOptions = {}) {
  resetMockDb(options.scenario ?? "signed-in");
  if (options.roles) alex().roles = [...options.roles] as never;
  if (options.modules) {
    mockUpdates.modules.running = [...options.modules] as never;
    mockUpdates.modules.configured = [...options.modules] as never;
  }
  setSessionForTest(null, "loading");
  const history = createMemoryHistory();
  history.set({ value: url });
  const result = render(() => (
    <MemoryRouter history={history} root={Root}>
      {buildRoutes()}
    </MemoryRouter>
  ));
  await loadSession();
  return { ...result, location: () => history.get() };
}
