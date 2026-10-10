// The toggle TGL-24 (the reveal policy of operator secrets) in the security settings of the
// mock API. It decorates the answers of the handler that already decorates the settings with
// TGL-23 (`updatesRoutes`): this one runs it, then adds the toggle to `toggles` and the
// banner, and stores the value on a PATCH. `handlers.ts` registers these routes before the
// updates routes so that they are asked first.
import { http, type HttpHandler } from "msw";
import type { components } from "../generated/schema";
import type { SecuritySettings, SecuritySettingsView, ToggleState } from "../types";
import { db } from "./db";
import { Problem } from "./reply";
import { REVEAL_DEFAULT, revealPolicy } from "./reveal-policy";
import { updatesRoutes } from "./routes-updates";
import { isRecord } from "./validate";

type RevealPolicy = components["schemas"]["RevealPolicy"];

const TOGGLE_ID = "TGL-24";
const SETTINGS_PATH = "/api/v1/settings/security";
const STEP_UP: readonly RevealPolicy["step_up"][] = ["session", "fresh", "passkey"];

function revealToggle(settings: SecuritySettings): ToggleState {
  const value = revealPolicy(settings);
  const fallback = REVEAL_DEFAULT[settings.profile];
  return {
    id: TOGGLE_ID,
    setting: "secret_reveal",
    value: { ...value },
    profile_default: { ...fallback },
    deviates: value.step_up !== fallback.step_up || value.bound_host_only !== fallback.bound_host_only,
    // No value is weaker than Home, so this toggle never raises the banner.
    weaker_than_home: false,
  };
}

function parseRevealPolicy(value: unknown): RevealPolicy {
  if (!isRecord(value) || typeof value.bound_host_only !== "boolean") {
    throw new Problem("sys.invalid_value", { status: 400, params: { name: "secret_reveal" } });
  }
  const stepUp = STEP_UP.find((s) => s === value.step_up);
  if (!stepUp) {
    throw new Problem("sys.invalid_value", { status: 400, params: { name: "secret_reveal.step_up" } });
  }
  return { step_up: stepUp, bound_host_only: value.bound_host_only };
}

/** The security view with TGL-24 added to the toggles and, when it deviates, to the banner. */
function withRevealToggle(view: SecuritySettingsView): SecuritySettingsView {
  if (view.toggles.some((t) => t.id === TOGGLE_ID)) return view;
  const toggle = revealToggle(db.settings);
  const banner = { ...view.banner, deviations: [...view.banner.deviations] };
  if (toggle.deviates) banner.deviations.push(TOGGLE_ID);
  return { ...view, toggles: [...view.toggles, toggle], banner };
}

/** The handler of the updates mock for a method: the one that answers the settings, to decorate. */
function settingsHandler(method: "GET" | "PATCH"): HttpHandler | undefined {
  return updatesRoutes.find((h) => {
    const info = (h as unknown as { info: { method: string; path: string } }).info;
    return info.method === method && info.path === SETTINGS_PATH;
  });
}

function jsonResponse(original: Response, view: SecuritySettingsView): Response {
  const headers = new Headers(original.headers);
  headers.delete("content-length");
  return new Response(JSON.stringify(view), { status: original.status, headers });
}

const getSecurity = http.get(SETTINGS_PATH, async ({ request, requestId }) => {
  const result = await settingsHandler("GET")?.run({ request, requestId });
  const original = result?.response;
  if (!original) return undefined;
  if (!original.ok) return original;
  return jsonResponse(original, withRevealToggle((await original.clone().json()) as SecuritySettingsView));
});

const patchSecurity = http.patch(SETTINGS_PATH, async ({ request, requestId }) => {
  let next: RevealPolicy | undefined;
  let profileSwitch = false;
  try {
    const body: unknown = await request.clone().json();
    if (isRecord(body)) {
      if (body.secret_reveal !== undefined && body.secret_reveal !== null) next = parseRevealPolicy(body.secret_reveal);
      profileSwitch = body.profile !== undefined;
    }
  } catch (error) {
    if (error instanceof Problem) return error.reply.toResponse();
  }
  const result = await settingsHandler("PATCH")?.run({ request, requestId });
  const original = result?.response;
  if (!original) return undefined;
  if (!original.ok) return original;
  // The settings mock committed the other members; the reveal policy goes on top of its answer.
  // A profile switch resets every toggle to the profile, this one included, unless the same
  // request sets it.
  const view = (await original.clone().json()) as SecuritySettingsView;
  if (next) {
    db.settings.secret_reveal = next;
    view.settings = { ...view.settings, secret_reveal: next };
  } else if (profileSwitch) {
    delete db.settings.secret_reveal;
    const { secret_reveal: _cleared, ...rest } = view.settings;
    view.settings = rest;
  }
  return jsonResponse(original, withRevealToggle(view));
});

export const revealPolicyRoutes: HttpHandler[] = [getSecurity, patchSecurity];
