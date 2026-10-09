// Seed data and test values of the mock API. Every password, code, token and fingerprint
// in the mock is a test value for this application only and protects nothing. Sample data
// stays in the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
// 2001:db8::/32, MACs 00-00-5E-00-53-xx, names under example.test).
//
// Times are offsets from "now" (the moment the db is reset), so the data never looks stale.
import type { NetworkFacts, NodeFacts, NodeRole, RoleName } from "../types";

// ---------------------------------------------------------------------------------
// Test values

/** The password of each seed user. The break-glass account never accepts its password. */
export const MOCK_PASSWORDS = {
  alex: "harbor-lantern-42-quartz",
  sam: "meadow-copper-17-violet",
  robin: "cobalt-willow-88-ember",
  breakglass: "granite-falcon-31-tundra",
} as const;

export type MockUserName = keyof typeof MOCK_PASSWORDS;

/** The TOTP code every enrolled authenticator accepts, and the enrolment of a new one. */
export const MOCK_TOTP_CODE = "123456";

/** The unused recovery codes of alex at the start of every scenario. */
export const MOCK_RECOVERY_CODES: readonly string[] = [
  "K7QM-4XD2",
  "9WTH-3RBN",
  "C2VJ-8PFA",
  "X5ZD-6KMG",
  "H4NE-7YQS",
  "R8BT-2CWK",
  "M3GF-9HVA",
  "P6JK-5ZXD",
  "D9SA-4TNE",
  "W2CY-7MQR",
];

/** The one-time token of first-run setup. */
export const MOCK_SETUP_TOKEN = "4F7K-9QXD-2MHT-8WCB";

/** SHA-256 of the internal CA certificate that setup reports (64 hexadecimal digits). */
export const MOCK_CA_FINGERPRINT = "3f1c8a9d5e7b2046a1d3c9e8f7a6b5c4d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7";

/** The version the status endpoint reports. */
export const MOCK_VERSION = "0.1.0-dev";

/**
 * Passwords the breached-password check knows (the stand-in for the HIBP corpus). Matching
 * is exact, like the real k-anonymity lookup.
 */
export const BREACHED_PASSWORDS: readonly string[] = [
  "0000",
  "1234",
  "123456",
  "12345678",
  "123456789",
  "1234567890",
  "111111",
  "000000",
  "password",
  "password1",
  "password123",
  "password1234",
  "Password123456",
  "passw0rd",
  "Passw0rd!Passw0rd",
  "P@ssw0rd1234!",
  "qwerty",
  "qwerty123",
  "qwertyuiop",
  "qwerty123456",
  "letmein",
  "letmein123",
  "letmein123456",
  "letmein-please-123",
  "welcome",
  "welcome1",
  "welcome12345",
  "iloveyou",
  "iloveyou123456",
  "admin",
  "adminadmin123",
  "changeme1234",
  "correct horse battery staple",
];

// ---------------------------------------------------------------------------------
// Users

/** Fixed ids of the seed users (UUID syntax, like the real ones). */
export const MOCK_USER_IDS: Readonly<Record<MockUserName, string>> = {
  alex: "0190d1c2-0000-7000-8000-00000000a001",
  sam: "0190d1c2-0000-7000-8000-00000000a002",
  robin: "0190d1c2-0000-7000-8000-00000000a003",
  breakglass: "0190d1c2-0000-7000-8000-00000000a004",
};

export interface SeedCredential {
  id: string;
  label: string;
  alg: number;
  aaguid: string;
  backup_eligible: boolean;
  backup_state: boolean;
  hardware_key: boolean;
  attestation: "none" | "certificate";
  created_days_ago: number;
  last_used_hours_ago: number | null;
}

export interface SeedUser {
  id: string;
  name: MockUserName;
  display_name: string;
  roles: RoleName[];
  disabled: boolean;
  break_glass: boolean;
  /** Whether the account has a password (the break-glass account logs in with its key only). */
  has_password: boolean;
  totp: boolean;
  credentials: SeedCredential[];
  recovery_codes: readonly string[];
  language: string | null;
  /** Locked at the start (lifts after the given minutes unless an administrator unlocks it). */
  locked_for_minutes: number | null;
  created_days_ago: number;
  last_login_hours_ago: number | null;
}

export const SEED_USERS: readonly SeedUser[] = [
  {
    id: MOCK_USER_IDS.alex,
    name: "alex",
    display_name: "Alex Example",
    roles: ["admin"],
    disabled: false,
    break_glass: false,
    has_password: true,
    totp: true,
    credentials: [
      {
        id: "kP3xq0fVn7tZ2cY8mRw1Ds5HjLbU6aNeG4oXiQyT9vE",
        label: "Laptop passkey",
        alg: -7,
        aaguid: "00000000000000000000000000000000",
        backup_eligible: true,
        backup_state: true,
        hardware_key: false,
        attestation: "none",
        created_days_ago: 41,
        last_used_hours_ago: 6,
      },
    ],
    recovery_codes: MOCK_RECOVERY_CODES,
    language: null,
    locked_for_minutes: null,
    created_days_ago: 120,
    last_login_hours_ago: 6,
  },
  {
    id: MOCK_USER_IDS.sam,
    name: "sam",
    display_name: "Sam Example",
    roles: ["operator"],
    disabled: false,
    break_glass: false,
    has_password: true,
    totp: false,
    credentials: [],
    recovery_codes: [],
    language: "sv",
    locked_for_minutes: 10,
    created_days_ago: 75,
    last_login_hours_ago: 27,
  },
  {
    id: MOCK_USER_IDS.robin,
    name: "robin",
    display_name: "Robin Example",
    roles: ["viewer"],
    disabled: true,
    break_glass: false,
    has_password: true,
    totp: false,
    credentials: [],
    recovery_codes: [],
    language: null,
    locked_for_minutes: null,
    created_days_ago: 60,
    last_login_hours_ago: 24 * 30,
  },
  {
    id: MOCK_USER_IDS.breakglass,
    name: "breakglass",
    display_name: "Break-glass account",
    roles: ["admin"],
    disabled: false,
    break_glass: true,
    has_password: false,
    totp: false,
    credentials: [
      {
        id: "Zr8mW1qTf5yK0nJc3xLd7VbHs2PaEuG9oXiQ4tN6vYe",
        label: "Safe key",
        alg: -7,
        aaguid: "0123456789abcdef0123456789abcdef",
        backup_eligible: false,
        backup_state: false,
        hardware_key: true,
        attestation: "certificate",
        created_days_ago: 118,
        last_used_hours_ago: null,
      },
    ],
    recovery_codes: [],
    language: null,
    locked_for_minutes: null,
    created_days_ago: 118,
    last_login_hours_ago: null,
  },
];

/** The attestation certificate of the break-glass key. */
export const MOCK_KEY_ATTESTATION = {
  certificate_sha256: "9b2e4f6a8c0d1e3f5a7b9c1d3e5f7a9b0c2d4e6f8a0b1c3d5e7f9a1b2c4d6e8f",
  subject: "CN=Example Security Key Attestation, O=Example Test",
} as const;

/** The sessions a user has besides the one they sign in with. */
export const OTHER_SESSIONS = [
  {
    user_agent: "Mozilla/5.0 (Android 14; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0",
    source_ip: "198.51.100.7",
    created_hours_ago: 30,
    last_seen_minutes_ago: 12,
  },
  {
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    source_ip: "192.0.2.41",
    created_hours_ago: 52,
    last_seen_minutes_ago: 60 * 5,
  },
] as const;

/** The client every new session comes from. */
export const CURRENT_CLIENT = {
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
  source_ip: "192.0.2.41",
} as const;

export const ROLE_DESCRIPTIONS: Readonly<Record<RoleName, string>> = {
  admin: "Full access, including users, security settings and the system",
  operator: "Reads and changes the IPAM inventory, runs imports and jobs; no administration",
  viewer: "Reads the IPAM inventory, jobs and imports",
};

/** The personal token alex starts with. */
export const SEED_TOKEN = {
  id: "0190d1c2-0000-7000-8000-00000000b001",
  name: "nightly export",
  prefix: "tko_Zq3v",
  created_days_ago: 20,
  expires_in_days: 70,
  last_used_hours_ago: 3,
} as const;

// ---------------------------------------------------------------------------------
// The node

export const NODE_NETWORKS: readonly NetworkFacts[] = [
  { id: "lan", name: "LAN", prefix: "192.0.2.0/24", vlan: 10, interface: "eth0", address: "192.0.2.13" },
  { id: "iot", name: "IoT", prefix: "198.51.100.0/24", vlan: 30, interface: "eth0.30", address: "198.51.100.13" },
  { id: "lab", name: "Lab", prefix: "203.0.113.0/25", vlan: 20, interface: "eth0.20", address: "203.0.113.13" },
  { id: "dmz", name: "DMZ", prefix: "203.0.113.128/26", vlan: 40, interface: "eth0.40", address: "203.0.113.133" },
];

export const NODE_ROLES_ALL: readonly NodeRole[] = ["controller", "dns", "dhcp", "probe"];

const GIB = 1024 ** 3;

/** What the node found about itself; the slow-disk variant has an SMR disk behind the data directory. */
export function nodeFacts(slowDisk: boolean): NodeFacts {
  return {
    name: "tenko1",
    os: "Linux",
    cores: 4,
    memory_bytes: 8 * GIB,
    addresses: ["192.0.2.13"],
    data_dir: slowDisk
      ? { path: "/srv/tenko", device: "/dev/sdb1", media: "smr", free_bytes: 412_000_000_000, fsync_p50_micros: 44_500 }
      : {
          path: "/var/lib/tenko",
          device: "/dev/nvme0n1p2",
          media: "nvme",
          free_bytes: 412_000_000_000,
          fsync_p50_micros: 900,
        },
    networks: NODE_NETWORKS.map((n) => ({ ...n })),
    roles: [...NODE_ROLES_ALL],
  };
}
