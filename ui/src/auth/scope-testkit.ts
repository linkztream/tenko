// Test helpers for display gating: a session of the scoped operator casey of the access seed
// (operator over 203.0.113.0/24 and below, viewer over 198.51.100.0/24 and below), and of the
// global roles, as the UI's own session.
import { waitFor } from "@solidjs/testing-library";
import { api } from "../api/client";
import { seedAccess, SCOPED_OPERATOR } from "../api/mock/access-store";
import { startSession } from "../api/mock/auth";
import { db, findUserByName, resetMockDb } from "../api/mock/db";
import type { RoleName } from "../api/types";
import { anchorIndexLoaded } from "./gate";
import { setSessionForTest } from "./session";

/** Signs the scoped operator casey in and waits until the anchor index of its grants is loaded. */
export async function signInScopedOperator(): Promise<void> {
  resetMockDb("signed-in");
  seedAccess();
  const casey = findUserByName(SCOPED_OPERATOR.name);
  if (!casey) throw new Error("the access seed has no scoped operator");
  startSession(casey, "password");
  setSessionForTest(await api.get("/api/v1/auth/session"));
  await waitFor(() => {
    if (!anchorIndexLoaded()) throw new Error("the anchor index is not loaded yet");
  });
}

/** Signs alex in with only the given global roles (a viewer, an operator, the auditor). */
export async function signInWithRoles(roles: RoleName[]): Promise<void> {
  resetMockDb("signed-in");
  const alex = db.users.find((u) => u.name === "alex");
  if (!alex) throw new Error("no alex");
  alex.roles = roles;
  setSessionForTest(await api.get("/api/v1/auth/session"));
}
