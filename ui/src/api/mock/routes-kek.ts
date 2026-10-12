// Mock routes of the `kek` API area (WP3.4a, IAM-15): the key-encryption key status of the
// controller (`GET /system/kek`) and the online rotation (`POST /system/kek/rotate`). One
// controller (node 1) with the systemd host-key protection and two generations; a rotation
// walks through its phases with the clock (requested, distributing, rewrapping, done), so the
// vault page can follow it. The rotation needs an administrator who signed in within the last
// five minutes (`auth.step_up_required` with `required: fresh`, as the server).
import type { components } from "../generated/schema";
import { requireAdmin, requireSession } from "./auth";
import { commit, db, onMockReset } from "./db";
import { ok, Problem, Reply } from "./reply";
import { route } from "./route";
import { DAY_MS, iso } from "./util";

type S = components["schemas"];
type Protection = S["KekProtectionView"];
type Rotation = S["KekRotationView"];

/** How long each phase of a mock rotation takes, in milliseconds. */
export const ROTATION_STEP_MS = 1500;
/** How recent a sign-in must be for a rotation (the server's fresh-authentication rule). */
const FRESH_MS = 5 * 60 * 1000;

const SYSTEMD_HOST: Protection = { code: "systemd_creds_host", text: "systemd-creds with the host key", weak: false };

interface KekState {
  generations: { id: string; created_at: string }[];
  active: string;
  epoch: number;
  rotation: (Rotation & { started: number }) | null;
  envelopes: number;
}

function fresh(): KekState {
  const now = Date.now();
  return {
    generations: [
      { id: "kek-000001", created_at: iso(now - 120 * DAY_MS) },
      { id: "kek-000002", created_at: iso(now - 30 * DAY_MS) },
    ],
    active: "kek-000002",
    epoch: 2,
    rotation: null,
    envelopes: 14,
  };
}

/** The state of the mock; tests may change it (a weak key, a failed rotation). */
export const kekState: KekState = fresh();

onMockReset(() => {
  Object.assign(kekState, fresh());
});

const PHASES: readonly S["KekRotationPhase"][] = ["requested", "distributing", "rewrapping", "done"];

/** Moves a running rotation on by the time that passed since it started. */
function advance(now: number): void {
  const rotation = kekState.rotation;
  if (!rotation || rotation.phase === "done" || rotation.phase === "failed") return;
  const index = Math.min(PHASES.length - 1, Math.floor((now - rotation.started) / ROTATION_STEP_MS));
  const phase = PHASES[index] ?? "requested";
  if (phase === rotation.phase) return;
  rotation.phase = phase;
  rotation.updated_at = iso(now);
  if (index >= 1 && !rotation.generation) {
    const id = `kek-${String(kekState.generations.length + 1).padStart(6, "0")}`;
    rotation.generation = id;
    kekState.generations.push({ id, created_at: iso(now) });
  }
  if (phase === "rewrapping") rotation.rewrapped = Math.floor(kekState.envelopes / 2);
  if (phase === "done" && rotation.generation) {
    rotation.rewrapped = kekState.envelopes;
    rotation.finished_at = iso(now);
    kekState.active = rotation.generation;
    kekState.epoch += 1;
  }
  commit("system");
}

/** The status `GET /system/kek` answers. */
export function kekStatus(): S["KekStatusView"] {
  advance(Date.now());
  const running = kekState.rotation;
  let rotation: Rotation | null = null;
  if (running) {
    const { started: _started, ...view } = running;
    rotation = view;
  }
  const warnings: S["StatusWarning"][] = [];
  if (rotation?.phase === "failed") {
    warnings.push({
      code: "vault.kek.rotation_failed",
      detail: `the last key rotation failed: ${rotation.error ?? "unknown"}`,
      params: { error: rotation.error ?? "" },
    });
  }
  return {
    node: 1,
    provider: "systemd_creds",
    protection: SYSTEMD_HOST,
    strongest: SYSTEMD_HOST,
    active: kekState.active,
    epoch: kekState.epoch,
    generations: kekState.generations.map((g) => ({
      id: g.id,
      active: g.id === kekState.active,
      loaded: true,
      created_at: g.created_at,
      protection: SYSTEMD_HOST,
    })),
    missing: [],
    refused: [],
    controllers: [
      {
        node: 1,
        provider: "systemd_creds",
        protection: SYSTEMD_HOST,
        strongest: SYSTEMD_HOST,
        updated_at: iso(db.startedAt),
      },
    ],
    rotation,
    warnings,
  };
}

export const kekRoutes = [
  // Any signed-in role that may read the system status (docs/secrets.md); the mock asks for a session.
  route("get", "/api/v1/system/kek", () => {
    requireSession();
    return ok(kekStatus());
  }),

  route("post", "/api/v1/system/kek/rotate", () => {
    const { session, user } = requireAdmin();
    if (Date.now() - session.created_at > FRESH_MS) {
      throw new Problem("auth.step_up_required", { params: { required: "fresh" } });
    }
    advance(Date.now());
    const running = kekState.rotation;
    if (running && running.phase !== "done" && running.phase !== "failed") {
      throw new Problem("vault.kek.rotation_in_progress", { status: 409, detail: "a key rotation is already running" });
    }
    const now = Date.now();
    kekState.rotation = {
      phase: "requested",
      requested_at: iso(now),
      requested_by: `user:${user.id}`,
      updated_at: iso(now),
      waiting_for: [],
      unreachable: [],
      rewrapped: 0,
      started: now,
    };
    commit("system");
    return new Reply(202, kekStatus());
  }),
];
