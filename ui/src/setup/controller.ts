// The state and the logic of the first-run wizard: one store for what the operator typed
// and chose, the live password check, the gates, navigation, the final request and what
// happens after it. Components only read from here and call its actions. Nothing is
// persisted; the password lives in memory until the request is sent.
import { createContext, createMemo, createSignal, onCleanup, untrack, useContext, batch, createEffect, type Accessor } from "solid-js";
import { createStore, type SetStoreFunction } from "solid-js/store";
import { api } from "../api/client";
import { errorMessage, isApiError } from "../api/problem";
import type {
  DataDirFacts,
  NetworkFacts,
  NodeFacts,
  NodeRole,
  PasswordCheckResult,
  PasswordPolicy,
  Profile,
  ProfileInfo,
  SetupRequest,
  SetupResult,
  SetupState,
  TlsMode,
} from "../api/types";
import { NODE_ROLES } from "../api/types";
import { establish } from "../auth/session";
import { CeremonyError, registerPasskey } from "../auth/webauthn";
import { locale, t } from "../i18n";
import {
  diskRisk,
  firstBlockedStep,
  FOCUS,
  gateFor,
  LAST_STEP,
  STEP_COUNT,
  type DiskRisk,
  type Gate,
  type GateInput,
  type PasswordCheckStatus,
} from "./gates";
import { generatePassword, generatorFor, type GeneratorKind } from "./generate";
import { parseProxyList, validateHostName } from "./validate";

/** How long the password must rest before it is sent to the server for judging. */
export const CHECK_DEBOUNCE_MS = 300;

/** The preset each profile sets (TGL-01), for the moment before the server's list arrives. */
const PRESET_OF: Readonly<Record<Profile, PasswordPolicy>> = {
  home: { preset: "pin" },
  standard: { preset: "standard" },
  hardened: { preset: "hardened" },
  lab: { preset: "pin" },
};

function scrollToTop(): void {
  document.documentElement.scrollTop = 0;
  document.body.scrollTop = 0;
}

/** Roles a profile starts with: Hardened scans passively only, so Probe starts unticked. */
export function defaultRoles(profile: Profile): Record<NodeRole, boolean> {
  return { controller: true, dns: true, dhcp: true, probe: profile !== "hardened" };
}

export interface WizardState {
  step: number;
  visited: boolean[];
  token: string;
  profile: Profile;
  labAck: boolean;
  userName: string;
  displayName: string;
  password: string;
  showPassword: boolean;
  generated: boolean;
  hostName: string;
  tlsMode: TlsMode;
  proxies: string;
  acceptSlowDisk: boolean;
  roles: Record<NodeRole, boolean>;
  rolesTouched: boolean;
  /** Probe networks by id: ticked or not. */
  networks: Record<string, boolean>;
  submitting: boolean;
  /** A reason the request was refused, shown on the step it belongs to. */
  problem: { step: number; error: unknown } | null;
}

function initialState(): WizardState {
  return {
    step: 0,
    visited: Array.from({ length: STEP_COUNT }, (_, i) => i === 0),
    token: "",
    profile: "home",
    labAck: false,
    userName: "",
    displayName: "",
    password: "",
    showPassword: false,
    generated: false,
    hostName: "",
    tlsMode: "internal_ca",
    proxies: "",
    acceptSlowDisk: false,
    roles: defaultRoles("home"),
    rolesTouched: false,
    networks: {},
    submitting: false,
    problem: null,
  };
}

interface CheckEntry {
  /** The input this answer belongs to; null before the first answer. */
  key: string | null;
  result: PasswordCheckResult | null;
  error: unknown;
}

export interface CodesState {
  /** `deferred`: the account has no second factor yet, so its codes come with the first passkey. */
  status: "loading" | "ready" | "deferred" | "error";
  codes: string[];
  error: unknown;
}

export interface AfterState {
  done: boolean;
  caFingerprint: string | null;
  codes: CodesState;
  codesSaved: boolean;
  passkey: { status: "none" | "waiting" | "added"; error: string | null };
}

function initialAfter(): AfterState {
  return {
    done: false,
    caFingerprint: null,
    codes: { status: "loading", codes: [], error: null },
    codesSaved: false,
    passkey: { status: "none", error: null },
  };
}

/** Where a refused request belongs: the step and the control to focus. */
export function problemTarget(err: unknown): { step: number; focus?: string } | null {
  if (!isApiError(err)) return null;
  if (err.is("auth.setup.token_invalid")) return { step: 0, focus: FOCUS.token };
  if (err.is("auth.setup.invalid_host_name")) return { step: 3, focus: FOCUS.hostName };
  const fields = [...err.fieldErrors.map((f) => f.field), err.params.field ?? ""];
  if (err.is("auth.password") || fields.some((f) => f.startsWith("admin.password"))) {
    return { step: 2, focus: FOCUS.password };
  }
  for (const field of fields) {
    if (field === "setup_token") return { step: 0, focus: FOCUS.token };
    if (field === "profile") return { step: 1 };
    if (field === "admin.name") return { step: 2, focus: FOCUS.userName };
    if (field.startsWith("admin.")) return { step: 2, focus: FOCUS.displayName };
    if (field === "host_name") return { step: 3, focus: FOCUS.hostName };
    if (field.startsWith("tls")) return { step: 3, focus: FOCUS.hostName };
    if (field === "accept_slow_disk") return { step: 4, focus: FOCUS.diskOverride };
    if (field === "roles" || field === "probe_networks") return { step: 5, focus: FOCUS.roleController };
  }
  return null;
}

export interface Wizard {
  state: WizardState;
  setState: SetStoreFunction<WizardState>;
  after: AfterState;
  // What the node told us
  loaded: Accessor<boolean>;
  loadError: Accessor<unknown>;
  load: () => Promise<void>;
  node: Accessor<NodeFacts | null>;
  profiles: Accessor<readonly ProfileInfo[]>;
  info: (profile: Profile) => ProfileInfo | undefined;
  networks: Accessor<readonly NetworkFacts[]>;
  dataDir: Accessor<DataDirFacts | null>;
  disk: Accessor<DiskRisk | null>;
  // Password
  policy: Accessor<PasswordPolicy>;
  generatorKind: Accessor<GeneratorKind>;
  breachOff: Accessor<boolean>;
  checkStatus: Accessor<PasswordCheckStatus>;
  checkResult: Accessor<PasswordCheckResult | null>;
  checkError: Accessor<unknown>;
  retryCheck: () => void;
  generate: () => void;
  // Navigation
  gate: (step?: number) => Gate | null;
  gateInput: Accessor<GateInput>;
  nudge: Accessor<number>;
  goTo: (step: number) => void;
  next: () => void;
  back: () => void;
  isDone: (step: number) => boolean;
  focusHeading: () => void;
  review: (step: number) => void;
  // Choices with side effects on other choices
  setProfile: (profile: Profile) => void;
  setRole: (role: NodeRole, on: boolean) => void;
  selectedNetworks: Accessor<string[]>;
  // Finishing
  submit: () => Promise<void>;
  finished: Accessor<boolean>;
  openGate: Accessor<Gate | null>;
  /** Runs `go` (default: open the application) unless the codes or the passkey are still due. */
  open: (go?: () => void) => void;
  loadCodes: () => Promise<void>;
  addPasskey: () => Promise<void>;
  setCodesSaved: (saved: boolean) => void;
}

export function createWizard(options: { onClosed: () => void; onOpen: () => void }): Wizard {
  const [state, setState] = createStore<WizardState>(initialState());
  const [after, setAfter] = createStore<AfterState>(initialAfter());
  const [setup, setSetup] = createSignal<SetupState | null>(null);
  const [loadError, setLoadError] = createSignal<unknown>(null);
  const [check, setCheck] = createSignal<CheckEntry>({ key: null, result: null, error: null });
  const [retry, setRetry] = createSignal(0);
  const [nudge, setNudge] = createSignal(0);
  const [finished, setFinished] = createSignal(false);

  // ---- What the node found

  const node = (): NodeFacts | null => setup()?.node ?? null;
  const profiles = (): readonly ProfileInfo[] => setup()?.profiles ?? [];
  const info = (profile: Profile): ProfileInfo | undefined => profiles().find((p) => p.profile === profile);
  const networks = (): readonly NetworkFacts[] => node()?.networks ?? [];
  const dataDir = (): DataDirFacts | null => node()?.data_dir ?? null;
  const disk = createMemo(() => diskRisk(dataDir()));

  async function load(): Promise<void> {
    setLoadError(null);
    try {
      // The node facts are a proposed extra of GET /setup (see api/types.ts).
      const res: SetupState = await api.get("/api/v1/setup");
      if (!res.open) {
        if (!finished()) options.onClosed();
        return;
      }
      batch(() => {
        setSetup(res);
        // Every network is ticked for the probe except a DMZ, which is a separate trust zone.
        setState("networks", Object.fromEntries((res.node?.networks ?? []).map((n) => [n.id, n.id !== "dmz"])));
      });
    } catch (err) {
      setLoadError(err);
    }
  }

  const loaded = (): boolean => setup() !== null;

  // ---- The password and its live check

  const policy = createMemo<PasswordPolicy>(
    () => info(state.profile)?.settings.password_policy ?? PRESET_OF[state.profile],
  );
  const generatorKind = createMemo(() => generatorFor(policy()));
  const breachOff = createMemo(() => (info(state.profile)?.settings.breach_check ?? "online") === "off");

  const checkKey = createMemo(() =>
    state.password === "" ? null : JSON.stringify([state.password, state.userName.trim(), state.profile]),
  );

  createEffect(() => {
    const key = checkKey();
    retry();
    if (key === null) {
      setCheck({ key: null, result: null, error: null });
      return;
    }
    const body = untrack(() => ({
      password: state.password,
      user_name: state.userName.trim() === "" ? undefined : state.userName.trim(),
      profile: state.profile,
    }));
    const controller = new AbortController();
    const timer = setTimeout(() => {
      void (async () => {
        try {
          const result = await api.post("/api/v1/auth/password/check", { body, signal: controller.signal });
          setCheck({ key, result, error: null });
        } catch (error) {
          if (!controller.signal.aborted) setCheck({ key, result: null, error });
        }
      })();
    }, CHECK_DEBOUNCE_MS);
    onCleanup(() => {
      clearTimeout(timer);
      controller.abort();
    });
  });

  const checkStatus = createMemo<PasswordCheckStatus>(() => {
    const key = checkKey();
    if (key === null) return "idle";
    const c = check();
    if (c.key !== key) return "pending";
    if (c.error) return "error";
    return c.result?.acceptable ? "ok" : "bad";
  });
  const checkResult = (): PasswordCheckResult | null => (check().key === checkKey() ? check().result : null);
  const checkError = (): unknown => (check().key === checkKey() ? check().error : null);

  function retryCheck(): void {
    setCheck({ key: null, result: null, error: null });
    setRetry((n) => n + 1);
  }

  function generate(): void {
    const policyNow = untrack(policy);
    const hostLabel = untrack(() => state.hostName.trim().toLowerCase().split(".")[0] ?? "");
    const avoid = [untrack(() => state.userName), hostLabel, untrack(() => node()?.name ?? ""), "tenko"];
    const length = policyNow.preset === "custom" ? Math.max(16, policyNow.min_length) : undefined;
    const password = generatePassword(untrack(generatorKind), length === undefined ? { avoid } : { avoid, length });
    batch(() => {
      setState("password", password);
      setState("showPassword", true);
      setState("generated", true);
    });
  }

  // ---- Gates and navigation

  const selectedNetworks = createMemo(() => networks().filter((n) => state.networks[n.id]).map((n) => n.id));

  const gateInput = createMemo<GateInput>(() => ({
    token: state.token,
    profile: state.profile,
    labAck: state.labAck,
    userName: state.userName,
    displayName: state.displayName,
    password: state.password,
    passwordKind: generatorKind(),
    passwordCheck: checkStatus(),
    hostName: state.hostName,
    tlsMode: state.tlsMode,
    proxies: state.proxies,
    diskRisk: disk() !== null,
    acceptSlowDisk: state.acceptSlowDisk,
    roles: state.roles,
    probeNetworks: selectedNetworks(),
    hasNetworks: networks().length > 0,
  }));

  const gate = (step: number = state.step): Gate | null => gateFor(step, gateInput());

  /** Focuses the control with this id, or the first control inside the element with it. */
  function focusById(id: string): void {
    const el = document.getElementById(id);
    if (!el) return;
    const control = el.matches("input, button, select, textarea")
      ? el
      : (el.querySelector<HTMLElement>("input, select, textarea") ?? el.querySelector<HTMLElement>("button"));
    if (control && !(control as HTMLButtonElement).disabled) control.focus();
  }

  function focusHeading(): void {
    document.getElementById("wz-title")?.focus();
  }

  function setStep(n: number, focus?: string): void {
    batch(() => {
      setState("step", n);
      setState("visited", n, true);
      if (state.problem && state.problem.step !== n) setState("problem", null);
    });
    scrollToTop();
    if (focus) focusById(focus);
    else focusHeading();
  }

  function refuse(g: Gate): void {
    setNudge((n) => n + 1);
    focusById(g.focus);
  }

  function goTo(n: number): void {
    if (finished() || n === state.step || n < 0 || n > LAST_STEP) return;
    let target = n;
    if (n > state.step) {
      for (let i = state.step; i < n; i += 1) {
        const g = gate(i);
        if (!g) continue;
        if (i === state.step) {
          refuse(g);
          return;
        }
        target = i;
        break;
      }
    }
    setStep(target);
  }

  function next(): void {
    if (finished()) return;
    if (state.step >= LAST_STEP) {
      void submit();
      return;
    }
    goTo(state.step + 1);
  }

  function back(): void {
    if (finished() || state.step === 0) return;
    setStep(state.step - 1);
  }

  /** A "Change" link of the summary: back to a step. */
  function review(step: number): void {
    if (finished()) return;
    setStep(step);
  }

  function isDone(step: number): boolean {
    if (finished()) return true;
    return step !== state.step && state.visited[step] === true && gate(step) === null;
  }

  // ---- Choices that touch other choices

  function setProfile(profile: Profile): void {
    batch(() => {
      setState("profile", profile);
      if (profile === "lab") setState("labAck", false);
      if (!state.rolesTouched) setState("roles", defaultRoles(profile));
      // Plain HTTP exists only in the Lab profile.
      if (profile !== "lab" && state.tlsMode === "plain") setState("tlsMode", "internal_ca");
      setState("problem", null);
    });
  }

  function setRole(role: NodeRole, on: boolean): void {
    batch(() => {
      setState("roles", role, on);
      setState("rolesTouched", true);
    });
  }

  // ---- Finishing

  function routeProblem(err: unknown): void {
    const target = problemTarget(err);
    const step = target?.step ?? LAST_STEP;
    batch(() => {
      setState("problem", { step, error: err });
      setState("step", step);
      setState("visited", step, true);
    });
    scrollToTop();
    if (target?.focus) focusById(target.focus);
    else focusHeading();
  }

  async function submit(): Promise<void> {
    if (state.submitting || finished()) return;
    const input = untrack(gateInput);
    const blocked = firstBlockedStep(input);
    if (blocked !== null) {
      setStep(blocked);
      const g = gateFor(blocked, input);
      if (g) refuse(g);
      return;
    }
    const host = validateHostName(state.hostName);
    if (!host.ok) return;
    const proxies = state.tlsMode === "reverse_proxy" ? parseProxyList(state.proxies).entries : [];
    const body: SetupRequest = {
      setup_token: state.token.trim(),
      profile: state.profile,
      admin: { name: state.userName.trim(), display_name: state.displayName.trim(), password: state.password },
      host_name: host.name,
      language: locale(),
      tls: { mode: state.tlsMode, trusted_proxies: proxies },
      accept_slow_disk: disk() !== null && state.acceptSlowDisk,
      roles: NODE_ROLES.filter((r) => state.roles[r]),
      probe_networks: state.roles.probe ? selectedNetworks() : [],
    };
    setState("submitting", true);
    setState("problem", null);
    let result: SetupResult;
    try {
      // The answer is the new session; a CA fingerprint is a proposed extra.
      result = await api.post("/api/v1/setup", { body });
    } catch (err) {
      routeProblem(err);
      setState("submitting", false);
      return;
    }
    batch(() => {
      setFinished(true);
      setAfter({ ...initialAfter(), done: true, caFingerprint: result.ca_fingerprint ?? null });
      // The password is in the account now; do not keep it around.
      setState("password", "");
      setState("showPassword", false);
      setState("submitting", false);
    });
    await establish(result);
    scrollToTop();
    focusHeading();
    await loadCodes();
  }

  async function loadCodes(): Promise<void> {
    setAfter("codes", { status: "loading", codes: [], error: null });
    try {
      const res = await api.post("/api/v1/auth/recovery-codes");
      batch(() => {
        setAfter("codes", { status: "ready", codes: res.codes, error: null });
        setAfter("codesSaved", false);
      });
    } catch (err) {
      // An account without a second factor has no codes to regenerate: they are created with
      // its first passkey or authenticator app.
      const noFactorYet =
        isApiError(err, "auth.invalid_request") &&
        (err.params.field === "recovery_codes" || err.fieldErrors.some((f) => f.field === "recovery_codes"));
      setAfter("codes", noFactorYet ? { status: "deferred", codes: [], error: null } : { status: "error", codes: [], error: err });
    }
  }

  async function addPasskey(): Promise<void> {
    if (after.passkey.status === "waiting") return;
    setAfter("passkey", { status: "waiting", error: null });
    try {
      const res = await registerPasskey({ label: t("setup.result.passkey_label") });
      setAfter("passkey", { status: "added", error: null });
      if (res.recovery_codes && res.recovery_codes.length > 0) {
        batch(() => {
          setAfter("codes", { status: "ready", codes: [...res.recovery_codes!], error: null });
          setAfter("codesSaved", false);
        });
      } else if (after.codes.status !== "ready") {
        await loadCodes();
      }
    } catch (err) {
      const message = err instanceof CeremonyError ? t(`auth.signin.ceremony.${err.reason}`) : errorMessage(err);
      setAfter("passkey", { status: "none", error: message });
    }
  }

  const openGate = createMemo<Gate | null>(() => {
    if (!finished()) return null;
    if (after.codes.status === "loading") return { message: "setup.gate.codes_loading", focus: FOCUS.codesAck, soft: true };
    if (after.codes.status === "ready" && !after.codesSaved) return { message: "setup.gate.codes_ack", focus: FOCUS.codesAck };
    if (state.profile === "hardened") {
      if (after.passkey.status === "waiting") return { message: "setup.gate.passkey_waiting", focus: FOCUS.passkey, soft: true };
      if (after.passkey.status !== "added") return { message: "setup.gate.passkey_required", focus: FOCUS.passkey };
    }
    return null;
  });

  function open(go: () => void = options.onOpen): void {
    const g = openGate();
    if (g) {
      refuse(g);
      return;
    }
    go();
  }

  function setCodesSaved(saved: boolean): void {
    setAfter("codesSaved", saved);
  }

  return {
    state,
    setState,
    after,
    loaded,
    loadError,
    load,
    node,
    profiles,
    info,
    networks,
    dataDir,
    disk,
    policy,
    generatorKind,
    breachOff,
    checkStatus,
    checkResult,
    checkError,
    retryCheck,
    generate,
    gate,
    gateInput,
    nudge,
    goTo,
    next,
    back,
    isDone,
    focusHeading,
    review,
    setProfile,
    setRole,
    selectedNetworks,
    submit,
    finished,
    openGate,
    open,
    loadCodes,
    addPasskey,
    setCodesSaved,
  };
}

const WizardContext = createContext<Wizard>();

export const WizardProvider = WizardContext.Provider;

export function useWizard(): Wizard {
  const w = useContext(WizardContext);
  if (!w) throw new Error("useWizard outside of the wizard");
  return w;
}
