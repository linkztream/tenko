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
import { toast } from "../components/toast";
import { writeModules } from "../updates/api";
import type { ModuleName } from "../updates/modules";
import { allModules, chosenModules, modulesGate } from "../updates/wizardModules";
import { CeremonyError, registerPasskey } from "../auth/webauthn";
import { locale, t } from "../i18n";
import {
  diskRisk,
  firstBlockedStep,
  FOCUS,
  gateFor,
  LAST_STEP,
  STEP_COUNT,
  STEP_IDS,
  type DiskRisk,
  type Gate,
  type GateInput,
  type PasswordCheckStatus,
} from "./gates";
import { createForwarder } from "../dns/forwarders/api";
import { checkRule, splitUpstreams, type ForwardTransport, type Upstream } from "../dns/forwarders/model";
import { generatePassword, generatorFor, type DnsChoice, type GeneratorKind } from "./generate";
import { parseProxyList, validateHostName } from "./validate";
// WP8.6: the DHCP step.
import { defaultPool, dhcpPlan, initialDhcp, saveDhcpScope, type DhcpOutcome, type DhcpPlan, type DhcpStepState } from "./dhcp";

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

/** The DNS step as typed: the upstreams, their transport and TLS name, and the preset's switches. */
export interface DnsStepState {
  upstreams: string;
  transport: ForwardTransport;
  tlsName: string;
  cache: boolean;
  /** Empty: the profile's bound (10,000 under Home, 100,000 otherwise). */
  cacheEntries: string;
  dot: boolean;
  doh: boolean;
  log: boolean;
  /** The operator changed a switch, so a change of profile no longer resets them. */
  touched: boolean;
}

/** The cache bound each profile starts with (`[dns.cache] entries` when it is not set). */
export function profileCacheEntries(profile: Profile): number {
  return profile === "home" ? 10_000 : 100_000;
}

/**
 * The switches a profile starts with. Home is the Home preset of P2-Q5: the cache on with its
 * bound, DoT and DoH served off, the query log off (TGL-15 makes it opt-in at home); the other
 * profiles log by default. The upstreams are never preset: the person enters them.
 */
export function dnsPreset(profile: Profile): Pick<DnsStepState, "cache" | "cacheEntries" | "dot" | "doh" | "log"> {
  return { cache: true, cacheEntries: String(profileCacheEntries(profile)), dot: false, doh: false, log: profile !== "home" };
}

function initialDns(profile: Profile): DnsStepState {
  return { upstreams: "", transport: "plain", tlsName: "", ...dnsPreset(profile), touched: false };
}

/** The choice of the DNS step as the generated configuration and the root rule take it. */
export function dnsChoice(dns: DnsStepState, profile: Profile): DnsChoice {
  const checked = checkRule({ suffix: ".", upstreams: dns.upstreams, transport: dns.transport, tlsName: dns.tlsName });
  const upstreams: Upstream[] = checked.ok ? checked.upstreams : [];
  const entries = Number(dns.cacheEntries.trim());
  const bound = dns.cacheEntries.trim() === "" || entries === profileCacheEntries(profile) ? null : entries;
  return {
    upstreams,
    transport: dns.transport,
    tlsName: checked.ok ? checked.tlsName : null,
    cache: dns.cache,
    cacheEntries: dns.cache ? bound : null,
    dot: dns.dot,
    doh: dns.doh,
    log: dns.log,
  };
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
  /** What the installation is for (OPS-25): the modules to run. At least one stays selected. */
  modules: Record<ModuleName, boolean>;
  /** Probe networks by id: ticked or not. */
  networks: Record<string, boolean>;
  /** The DNS step (P2-Q5). */
  dns: DnsStepState;
  // WP8.6: the DHCP step.
  /** The DHCP step: the first scope and the listener. */
  dhcp: DhcpStepState;
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
    modules: allModules(),
    networks: {},
    dns: initialDns("home"),
    // WP8.6: filled from the node's networks when they arrive.
    dhcp: initialDhcp(),
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

/** What became of the upstreams after setup: stored as the root forwarding rule, or not. */
export type DnsOutcome = { status: "none" } | { status: "saved" } | { status: "failed"; error: unknown };

export interface AfterState {
  done: boolean;
  dns: DnsOutcome;
  // WP8.6: what became of the first DHCP scope.
  dhcp: DhcpOutcome;
  caFingerprint: string | null;
  codes: CodesState;
  codesSaved: boolean;
  passkey: { status: "none" | "waiting" | "added"; error: string | null };
}

function initialAfter(): AfterState {
  return {
    done: false,
    dns: { status: "none" },
    // WP8.6
    dhcp: { status: "none" },
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
  setModule: (module: ModuleName, on: boolean) => void;
  selectedNetworks: Accessor<string[]>;
  /** Whether the DNS step applies: the DNS module and the `dns` role are chosen. */
  dnsWanted: Accessor<boolean>;
  setDns: <K extends keyof DnsStepState>(key: K, value: DnsStepState[K]) => void;
  /** Sets the switches of the Home preset (or of the chosen profile). */
  applyDnsPreset: () => void;
  // WP8.6: the DHCP step.
  /** Whether the DHCP step applies: the DHCP module and the `dhcp` role are chosen. */
  dhcpWanted: Accessor<boolean>;
  setDhcp: <K extends keyof DhcpStepState>(key: K, value: DhcpStepState[K]) => void;
  /** The scope the DHCP step describes, or null while it has a problem or is set up later. */
  dhcpPlan: Accessor<DhcpPlan | null>;
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
        // WP8.6: the DHCP step starts from the node's first IPv4 network.
        setState("dhcp", initialDhcp(res.node?.networks ?? []));
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
  const dnsWanted = createMemo(() => state.modules.dns && state.roles.dns);
  // WP8.6: the DHCP step applies with the DHCP module and the `dhcp` role.
  const dhcpWanted = createMemo(() => state.modules.dhcp && state.roles.dhcp);
  const plan = createMemo(() => dhcpPlan(state.dhcp, dhcpWanted()));

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
    dns: {
      wanted: dnsWanted(),
      upstreams: state.dns.upstreams,
      transport: state.dns.transport,
      tlsName: state.dns.tlsName,
      cache: state.dns.cache,
      cacheEntries: state.dns.cacheEntries,
    },
    // WP8.6
    dhcp: { wanted: dhcpWanted(), state: { ...state.dhcp } },
  }));

  // The roles step also holds the module choice, which has its own gate (src/updates/wizardModules.ts).
  const gate = (step: number = state.step): Gate | null =>
    gateFor(step, gateInput()) ?? (STEP_IDS[step] === "roles" ? modulesGate(state.modules) : null);

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
      if (!state.dns.touched) setState("dns", { ...state.dns, ...dnsPreset(profile) });
      // Plain HTTP exists only in the Lab profile.
      if (profile !== "lab" && state.tlsMode === "plain") setState("tlsMode", "internal_ca");
      setState("problem", null);
    });
  }

  function setModule(module: ModuleName, on: boolean): void {
    setState("modules", module, on);
  }

  function setDns<K extends keyof DnsStepState>(key: K, value: DnsStepState[K]): void {
    batch(() => {
      setState("dns", key, value);
      if (key === "cache" || key === "cacheEntries" || key === "dot" || key === "doh" || key === "log") setState("dns", "touched", true);
    });
  }

  function applyDnsPreset(): void {
    setState("dns", { ...state.dns, ...dnsPreset("home"), touched: true });
  }

  // WP8.6: a change of the network proposes its pool while the pool was the proposal of the old one.
  function setDhcp<K extends keyof DhcpStepState>(key: K, value: DhcpStepState[K]): void {
    batch(() => {
      if (key === "network") {
        const old = defaultPool(state.dhcp.network);
        const proposed = defaultPool(String(value));
        const untouched = (!old && state.dhcp.poolFirst === "" && state.dhcp.poolLast === "") || (old && old.first === state.dhcp.poolFirst && old.last === state.dhcp.poolLast);
        if (untouched && proposed) setState("dhcp", { poolFirst: proposed.first, poolLast: proposed.last });
      }
      setState("dhcp", key, value);
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
    const noModules = untrack(() => modulesGate(state.modules));
    if (noModules) {
      setStep(STEP_IDS.indexOf("roles"));
      refuse(noModules);
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
    await saveModules();
    await saveDns();
    // WP8.6: the first DHCP scope.
    await saveDhcp();
    scrollToTop();
    focusHeading();
    await loadCodes();
  }

  /**
   * Tells the server what the installation is for (OPS-25), when it is not for everything. Needs
   * the new session. `tenko.toml` may pin the modules (409 `modules.pinned`): then the file wins
   * and there is nothing to tell. Any other refusal is shown; the choice can be made again later.
   */
  async function saveModules(): Promise<void> {
    const chosen = chosenModules(state.modules);
    if (chosen.length === Object.keys(state.modules).length) return;
    try {
      await writeModules(chosen);
    } catch (err) {
      if (isApiError(err, "modules.pinned")) return;
      toast({ kind: "bad", title: t("setup.modules.save_failed"), body: errorMessage(err) });
    }
  }

  /**
   * Stores the upstreams of the DNS step as the root forwarding rule (the default forwarder of
   * the store, which wins over `[dns] forwarders` of the file), with the new session. A refusal
   * (the DNS module not running yet, a rule that exists) leaves the generated configuration and
   * the forwarders page as the way; the result step says which.
   */
  async function saveDns(): Promise<void> {
    if (!dnsWanted() || splitUpstreams(state.dns.upstreams).length === 0) return;
    const choice = dnsChoice(state.dns, state.profile);
    if (choice.upstreams.length === 0) return;
    try {
      await createForwarder({
        suffix: ".",
        upstreams: [...choice.upstreams],
        transport: choice.transport,
        tls_name: choice.tlsName,
        description: null,
      });
      setAfter("dns", { status: "saved" });
    } catch (error) {
      setAfter("dns", { status: "failed", error });
    }
  }

  // WP8.6
  /**
   * Writes the first DHCP scope of the DHCP step through the configuration routes with the new
   * session: the IPAM network, the pool, the scope and its router and DNS options. A refusal (the
   * DHCP module not running yet, a network or range that exists) is shown on the result step with
   * the step it stopped at; the DHCP pages are then the way. The listener goes into `tenko.toml`.
   */
  async function saveDhcp(): Promise<void> {
    const p = untrack(plan);
    if (!p) return;
    setAfter("dhcp", await saveDhcpScope(p));
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
    setModule,
    selectedNetworks,
    dnsWanted,
    setDns,
    applyDnsPreset,
    // WP8.6
    dhcpWanted,
    setDhcp,
    dhcpPlan: plan,
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
