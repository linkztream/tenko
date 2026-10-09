// The in-memory state of the mock API, the scenarios it can start in and the journal that
// feeds the event stream. Every write goes through `commit`, which raises the revision and
// appends to the journal, so revisions increase on every write and everything that has a
// `revision` carries one.
import type { ObjectRef, Topic } from "../events";
import type {
  AccountLock,
  AuthStrength,
  CredentialInfo,
  JobState,
  NodeFacts,
  NodeRole,
  RoleName,
  SecuritySettings,
  SecuritySettingsView,
  SessionSummary,
  TlsMode,
  TokenInfo,
  UserInfo,
} from "../types";
import {
  CURRENT_CLIENT,
  MOCK_KEY_ATTESTATION,
  MOCK_PASSWORDS,
  MOCK_SETUP_TOKEN,
  MOCK_USER_IDS,
  NODE_ROLES_ALL,
  OTHER_SESSIONS,
  SEED_JOBS,
  SEED_TOKEN,
  SEED_USERS,
  TICKER_JOBS,
  nodeFacts,
  type SeedCredential,
  type SeedUser,
} from "./fixtures";
import { banner, profileSettings, toggleStates } from "./profiles";
import { DAY_MS, HOUR_MS, MINUTE, iso, randomId, uuidHandle } from "./util";

// ---------------------------------------------------------------------------------
// Scenarios

export type MockScenario = "setup" | "setup-slow-disk" | "signed-out" | "signed-in" | "lab" | "weak";

export const MOCK_SCENARIOS: readonly MockScenario[] = [
  "setup",
  "setup-slow-disk",
  "signed-out",
  "signed-in",
  "lab",
  "weak",
];

export const DEFAULT_SCENARIO: MockScenario = "signed-out";

export function isMockScenario(value: unknown): value is MockScenario {
  return typeof value === "string" && (MOCK_SCENARIOS as readonly string[]).includes(value);
}

/** The revision a fresh db starts at. */
export const INITIAL_REVISION = 100;
/** Events the journal keeps for replay (the server's ring holds 256 frames as well). */
export const JOURNAL_CAPACITY = 256;

// ---------------------------------------------------------------------------------
// State

export interface MockUser {
  id: string;
  name: string;
  display_name: string;
  roles: RoleName[];
  disabled: boolean;
  break_glass: boolean;
  lock: AccountLock | null;
  /** The password in clear text (it is a test value); null for an account without one. */
  password: string | null;
  totp: boolean;
  credentials: CredentialInfo[];
  recovery_codes: string[];
  password_change_required: boolean;
  language: string | null;
  created_at: string;
  last_login_at: string | null;
  revision: number;
  /** The WebAuthn user handle (base64url of 16 bytes). */
  handle: string;
}

export interface MockSession {
  id: string;
  user_id: string;
  strength: AuthStrength;
  created_at: number;
  last_seen_at: number;
  expires_at: number;
  absolute_expires_at: number;
  source_ip: string;
  user_agent: string;
}

export interface MockToken {
  user_id: string;
  info: TokenInfo;
}

/** A password login that waits for its second factor. */
export interface MockChallenge {
  id: string;
  user_id: string;
  expires_at: number;
}

/** A WebAuthn ceremony between its start and finish. */
export interface MockCeremony {
  id: string;
  kind: "login" | "register";
  challenge: string;
  expires_at: number;
  /** Login: the account the options were made for, if any. */
  user_id: string | null;
  /** Login: the password challenge this passkey completes. */
  challenge_id: string | null;
  break_glass: boolean;
  /** Login: a user name was given that no account has. */
  unknown_user: boolean;
  /** Register: the label and kind of the new credential. */
  label: string | null;
  security_key: boolean;
}

export interface MockEnrolment {
  id: string;
  user_id: string;
  secret: string;
  expires_at: number;
}

export interface ThrottleEntry {
  failures: number;
  locked_until: number;
}

export interface Installation {
  host_name: string | null;
  language: string | null;
  tls: { mode: TlsMode; trusted_proxies: string[] };
  roles: NodeRole[];
}

export interface MockEventData {
  topic: Topic;
  revision?: number;
  objects: ObjectRef[];
  deleted: ObjectRef[];
  audit: number[];
  tables: string[];
  kind?: string;
  params: Record<string, string>;
}

/** One event of the journal. `id` is the revision; null for an alarm that is no store change. */
export interface MockEvent {
  id: number | null;
  topic: Topic;
  data: MockEventData;
}

export interface MockDb {
  scenario: MockScenario;
  revision: number;
  startedAt: number;
  setupOpen: boolean;
  setupToken: string;
  node: NodeFacts;
  installation: Installation;
  settings: SecuritySettings;
  settingsRevision: number;
  vaultHasOperatorSecrets: boolean;
  users: MockUser[];
  sessions: MockSession[];
  currentSessionId: string | null;
  /** Users whose other sessions were created already. */
  seededSessionUsers: Set<string>;
  tokens: MockToken[];
  challenges: Map<string, MockChallenge>;
  ceremonies: Map<string, MockCeremony>;
  enrolments: Map<string, MockEnrolment>;
  throttle: Map<string, ThrottleEntry>;
  jobs: MockJob[];
  journal: MockEvent[];
}

/** A job as the mock keeps it; routes turn it into the document's JobSummary. */
export interface MockJob {
  id: string;
  kind: string;
  state: JobState;
  title: string;
  /** 0 to 1. */
  progress: number | null;
  created_at: string;
}

/** The state. One object for the life of the module: `resetMockDb` replaces its members. */
export const db: MockDb = createDb(DEFAULT_SCENARIO);

// ---------------------------------------------------------------------------------
// Journal and subscribers

type Listener = (event: MockEvent) => void;
type ResetListener = (revision: number) => void;

const listeners = new Set<Listener>();
const resetListeners = new Set<ResetListener>();

/** Calls `listener` for every event, journaled or not. Returns the unsubscribe function. */
export function subscribeEvents(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Calls `listener` after the db was reset. */
export function onMockReset(listener: ResetListener): () => void {
  resetListeners.add(listener);
  return () => resetListeners.delete(listener);
}

function emptyData(topic: Topic): MockEventData {
  return { topic, objects: [], deleted: [], audit: [], tables: [], params: {} };
}

/** Raises the revision, appends to the journal and tells the open streams. */
export function recordEvent(topic: Topic, change: Partial<Omit<MockEventData, "topic" | "revision">> = {}): MockEvent {
  db.revision += 1;
  const data: MockEventData = { ...emptyData(topic), ...change, topic, revision: db.revision };
  const event: MockEvent = { id: db.revision, topic, data };
  db.journal.push(event);
  if (db.journal.length > JOURNAL_CAPACITY) db.journal.splice(0, db.journal.length - JOURNAL_CAPACITY);
  publish(event);
  return event;
}

/** An event that is no store change (an alarm): no revision, no id, not replayed. */
export function recordAlarm(topic: Topic, change: Partial<Omit<MockEventData, "topic" | "revision">> = {}): MockEvent {
  const event: MockEvent = { id: null, topic, data: { ...emptyData(topic), ...change, topic } };
  publish(event);
  return event;
}

function publish(event: MockEvent): void {
  for (const listener of [...listeners]) listener(event);
}

/**
 * Commits a write: records the event and stamps the revision on the records it changed.
 * Every write handler of the mock ends here.
 */
export function commit(
  topic: Topic,
  change: Partial<Omit<MockEventData, "topic" | "revision">> = {},
  touched: { revision: number }[] = [],
): MockEvent {
  const event = recordEvent(topic, change);
  for (const record of touched) record.revision = db.revision;
  return event;
}

/** The change set of a write to one user. */
export function userChange(user: { id: string }): Partial<MockEventData> {
  return { objects: [{ kind: "user", id: user.id }], tables: ["auth.users"] };
}

// ---------------------------------------------------------------------------------
// Lookups

export function findUserByName(name: string): MockUser | undefined {
  const key = name.trim().toLowerCase();
  return db.users.find((u) => u.name.toLowerCase() === key);
}

export function findUser(id: string): MockUser | undefined {
  return db.users.find((u) => u.id === id);
}

export function isAdmin(user: { roles: readonly RoleName[] }): boolean {
  return user.roles.includes("admin");
}

/** Administrators other than `except` that count for the last-administrator rule. */
export function otherActiveAdmins(except: string): MockUser[] {
  return db.users.filter((u) => u.id !== except && isAdmin(u) && !u.disabled && !u.break_glass);
}

// ---------------------------------------------------------------------------------
// Sessions

export interface SessionOptions {
  now?: number;
  user_agent?: string;
  source_ip?: string;
}

/** A session record for `user` under the lifetimes of `settings`. */
export function newSessionRecord(
  settings: SecuritySettings,
  user: { id: string },
  strength: AuthStrength,
  options: SessionOptions = {},
): MockSession {
  const now = options.now ?? Date.now();
  const absolute = now + settings.session.absolute_secs * 1000;
  return {
    id: randomId(),
    user_id: user.id,
    strength,
    created_at: now,
    last_seen_at: now,
    expires_at: Math.min(now + settings.session.idle_secs * 1000, absolute),
    absolute_expires_at: absolute,
    source_ip: options.source_ip ?? CURRENT_CLIENT.source_ip,
    user_agent: options.user_agent ?? CURRENT_CLIENT.user_agent,
  };
}

/** Adds the sessions a user has from other clients, once. */
export function ensureOtherSessions(user: MockUser): void {
  if (db.seededSessionUsers.has(user.id)) return;
  db.seededSessionUsers.add(user.id);
  const now = Date.now();
  for (const other of OTHER_SESSIONS) {
    const session = newSessionRecord(db.settings, user, "password", {
      now: now - other.created_hours_ago * HOUR_MS,
      user_agent: other.user_agent,
      source_ip: other.source_ip,
    });
    session.last_seen_at = now - other.last_seen_minutes_ago * MINUTE;
    // Seeded sessions are alive now, whatever the profile says about idle time.
    session.expires_at = now + db.settings.session.idle_secs * 1000;
    session.absolute_expires_at = Math.max(session.absolute_expires_at, session.expires_at);
    db.sessions.push(session);
  }
}

export function toSessionSummary(session: MockSession): SessionSummary {
  return {
    id: session.id,
    created_at: iso(session.created_at),
    last_seen_at: iso(session.last_seen_at),
    expires_at: iso(session.expires_at),
    strength: session.strength,
    source_ip: session.source_ip,
    user_agent: session.user_agent,
    current: session.id === db.currentSessionId,
  };
}

// ---------------------------------------------------------------------------------
// Views

function attestationOf(seed: SeedCredential): CredentialInfo["attestation"] {
  return seed.attestation === "certificate"
    ? { kind: "certificate", anchored: true, ...MOCK_KEY_ATTESTATION }
    : { kind: "none" };
}

export function toUserInfo(user: MockUser): UserInfo {
  const now = Date.now();
  const lock = user.lock && (user.lock.until_unlock || Date.parse(user.lock.until) > now) ? { ...user.lock } : null;
  const info: UserInfo = {
    id: user.id,
    name: user.name,
    display_name: user.display_name,
    roles: [...user.roles],
    disabled: user.disabled,
    break_glass: user.break_glass,
    lock,
    factors: {
      password: user.password !== null,
      totp: user.totp,
      webauthn: user.credentials.length,
      hardware_keys: user.credentials.filter((c) => c.hardware_key).length,
      recovery_codes: user.recovery_codes.length,
    },
    password_change_required: user.password_change_required,
    created_at: user.created_at,
    last_login_at: user.last_login_at,
    revision: user.revision,
  };
  if (user.language) info.language = user.language;
  return info;
}

export function toTokenInfo(token: MockToken): TokenInfo {
  return { ...token.info };
}

export function settingsView(): SecuritySettingsView {
  return {
    settings: structuredClone(db.settings),
    toggles: toggleStates(db.settings),
    banner: banner(db.settings),
    vault_has_operator_secrets: db.vaultHasOperatorSecrets,
    revision: db.settingsRevision,
  };
}

// ---------------------------------------------------------------------------------
// Jobs

let tickerCounter = 0;

/**
 * One step of the job ticker: the running job advances, or finishes and the next one
 * starts. Records a `jobs` event and returns it.
 */
export function advanceMockJobs(): MockEvent {
  const now = Date.now();
  let job = db.jobs.find((j) => j.state === "running");
  if (!job) {
    const seed = TICKER_JOBS[tickerCounter % TICKER_JOBS.length] ?? { kind: "import.apply", title: "Apply import" };
    tickerCounter += 1;
    job = { id: randomId(), kind: seed.kind, state: "running", title: seed.title, progress: 0.05, created_at: iso(now) };
    db.jobs.unshift(job);
  } else {
    const progress = Math.round(((job.progress ?? 0) + 0.07) * 100) / 100;
    if (progress >= 1) {
      job.state = "succeeded";
      job.progress = 1;
    } else {
      job.progress = progress;
    }
  }
  // Keep the list short: the oldest finished jobs fall off.
  const finished = db.jobs.filter((j) => j.state === "succeeded");
  for (const old of finished.slice(5)) db.jobs.splice(db.jobs.indexOf(old), 1);
  return recordEvent("jobs", { objects: [{ kind: "job", id: job.id }] });
}

// ---------------------------------------------------------------------------------
// Creating the state

function seedCredential(seed: SeedCredential, now: number): CredentialInfo {
  const info: CredentialInfo = {
    id: seed.id,
    label: seed.label,
    alg: seed.alg,
    aaguid: seed.aaguid,
    created_at: iso(now - seed.created_days_ago * DAY_MS),
    backup_eligible: seed.backup_eligible,
    backup_state: seed.backup_state,
    hardware_key: seed.hardware_key,
    attestation: attestationOf(seed),
  };
  if (seed.last_used_hours_ago !== null) info.last_used_at = iso(now - seed.last_used_hours_ago * HOUR_MS);
  return info;
}

function seedUser(seed: SeedUser, now: number): MockUser {
  return {
    id: seed.id,
    name: seed.name,
    display_name: seed.display_name,
    roles: [...seed.roles],
    disabled: seed.disabled,
    break_glass: seed.break_glass,
    lock:
      seed.locked_for_minutes === null
        ? null
        : { since: iso(now - 5 * MINUTE), until: iso(now + seed.locked_for_minutes * MINUTE), until_unlock: false },
    password: seed.has_password ? MOCK_PASSWORDS[seed.name] : null,
    totp: seed.totp,
    credentials: seed.credentials.map((c) => seedCredential(c, now)),
    recovery_codes: [...seed.recovery_codes],
    password_change_required: false,
    language: seed.language,
    created_at: iso(now - seed.created_days_ago * DAY_MS),
    last_login_at: seed.last_login_hours_ago === null ? null : iso(now - seed.last_login_hours_ago * HOUR_MS),
    revision: INITIAL_REVISION,
    handle: uuidHandle(seed.id),
  };
}

function settingsFor(scenario: MockScenario): SecuritySettings {
  switch (scenario) {
    case "lab":
      return profileSettings("lab");
    case "weak":
      // Home with one toggle weaker than Home: lockout off.
      return { ...profileSettings("home"), lockout: "off" };
    default:
      return profileSettings("standard");
  }
}

function createDb(scenario: MockScenario): MockDb {
  const now = Date.now();
  const setup = scenario === "setup" || scenario === "setup-slow-disk";
  const settings = settingsFor(scenario);
  const users = setup ? [] : SEED_USERS.map((u) => seedUser(u, now));
  const state: MockDb = {
    scenario,
    revision: INITIAL_REVISION,
    startedAt: now - 3 * HOUR_MS,
    setupOpen: setup,
    setupToken: MOCK_SETUP_TOKEN,
    node: nodeFacts(scenario === "setup-slow-disk"),
    installation: {
      host_name: setup ? null : "tenko1.example.test",
      language: null,
      tls: { mode: scenario === "lab" ? "plain" : "internal_ca", trusted_proxies: [] },
      roles: [...NODE_ROLES_ALL],
    },
    settings,
    settingsRevision: INITIAL_REVISION,
    vaultHasOperatorSecrets: false,
    users,
    sessions: [],
    currentSessionId: null,
    seededSessionUsers: new Set(),
    tokens: [],
    challenges: new Map(),
    ceremonies: new Map(),
    enrolments: new Map(),
    throttle: new Map(),
    jobs: SEED_JOBS.map((j) => ({
      id: j.id,
      kind: j.kind,
      state: j.state,
      title: j.title,
      progress: j.progress,
      created_at: iso(now - j.created_minutes_ago * MINUTE),
    })),
    journal: [],
  };

  const alex = users.find((u) => u.id === MOCK_USER_IDS.alex);
  if (alex) {
    state.tokens.push({
      user_id: alex.id,
      info: {
        id: SEED_TOKEN.id,
        name: SEED_TOKEN.name,
        prefix: SEED_TOKEN.prefix,
        created_at: iso(now - SEED_TOKEN.created_days_ago * DAY_MS),
        expires_at: iso(now + SEED_TOKEN.expires_in_days * DAY_MS),
        last_used_at: iso(now - SEED_TOKEN.last_used_hours_ago * HOUR_MS),
      },
    });
  }
  const signedIn = scenario === "signed-in" || scenario === "lab" || scenario === "weak";
  if (signedIn && alex) {
    const session = newSessionRecord(settings, alex, "passkey", { now });
    state.sessions.push(session);
    state.currentSessionId = session.id;
  }
  return state;
}

/**
 * Starts over in a scenario (default `signed-out`): the state, the journal and the revision
 * are replaced, and the open event streams are told to reload.
 */
export function resetMockDb(scenario: MockScenario = DEFAULT_SCENARIO): void {
  const fresh = createDb(scenario);
  Object.assign(db, fresh);
  const alex = db.users.find((u) => u.id === MOCK_USER_IDS.alex);
  if (alex && db.currentSessionId) ensureOtherSessions(alex);
  for (const listener of [...resetListeners]) listener(db.revision);
}
