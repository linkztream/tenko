// WP6.3: the DNSSEC tab of the zone page. Switch signing on through the zone's policy, see the
// keys and the DS records to put at the parent, copy them, start a ZSK rollover and see the new
// key; a viewer reads the state and gets no controls; Swedish.
//
// THESE SCENARIOS FAKE THE DNS ROUTES (support/dns-mock.ts, which says why) and, on top of that
// fake, the two DNSSEC routes and the signing policy of a zone patch: the signer here answers at
// once (a KSK and a ZSK with made-up keys, the DS of the KSK) and a rollover's job has already
// run when it is answered. The rest of the API is the real server.

import { randomBytes, randomUUID } from "node:crypto";
import type { Page, Route } from "@playwright/test";
import { signInAsViewer } from "./support/accounts";
import { FakeDns } from "./support/dns-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

const ZONE = "example.test";

interface Key {
  id: string;
  role: "ksk" | "zsk" | "csk";
  algorithm: "ecdsa_p256_sha256" | "ed25519";
  key_tag: number;
  state: "published" | "active" | "retired" | "removed";
  dnskey: Record<string, unknown>;
  published: string;
  activated: string;
  retired?: string;
}

/** The DNSSEC routes of one zone, answered in the browser over a FakeDns zone. */
class FakeSigner {
  keys: Key[] = [];
  digests = new Map<number, string>();
  rollovers: string[] = [];
  serial: number | null = null;

  private constructor(private readonly dns: FakeDns) {}

  static async install(page: Page, dns: FakeDns): Promise<FakeSigner> {
    const fake = new FakeSigner(dns);
    // Registered after FakeDns, so these handlers run first and fall back to it.
    await page.route(/\/api\/v1\/dns\/zones\/[^/?]+(\?|$)/, (route) => fake.patch(route));
    await page.route(/\/api\/v1\/dns\/zones\/[^/]+\/dnssec(\/rollover)?(\?|$)/, (route) => fake.dnssec(route));
    return fake;
  }

  private zone() {
    const zone = this.dns.zone(ZONE);
    if (!zone) throw new Error("no zone");
    return zone;
  }

  private key(role: Key["role"], algorithm: Key["algorithm"]): Key {
    const taken = new Set(this.keys.map((k) => k.key_tag));
    let tag = randomBytes(2).readUInt16BE(0);
    while (taken.has(tag)) tag = randomBytes(2).readUInt16BE(0);
    const now = new Date().toISOString();
    this.digests.set(tag, randomBytes(32).toString("hex"));
    return {
      id: randomUUID(),
      role,
      algorithm,
      key_tag: tag,
      state: "active",
      dnskey: { type: "DNSKEY", flags: role === "zsk" ? 256 : 257, protocol: 3, algorithm: algorithm === "ed25519" ? 15 : 13, public_key: randomBytes(64).toString("hex") },
      published: now,
      activated: now,
    };
  }

  private async patch(route: Route): Promise<void> {
    const request = route.request();
    if (request.method() !== "PATCH") return route.fallback();
    const body = JSON.parse(request.postData() ?? "{}") as { dnssec?: Record<string, unknown> };
    if (body.dnssec) {
      const zone = this.zone() as { dnssec?: Record<string, unknown>; soa_serial: number };
      zone.dnssec = { ...zone.dnssec, ...body.dnssec };
      const now = new Date().toISOString();
      if (zone.dnssec.mode === "online") {
        const algorithm = (zone.dnssec.algorithm as Key["algorithm"] | undefined) ?? "ecdsa_p256_sha256";
        for (const role of zone.dnssec.csk ? (["csk"] as const) : (["ksk", "zsk"] as const)) {
          const retired = this.keys.find((k) => k.role === role && k.state === "retired");
          if (retired) retired.state = "active";
          else if (!this.keys.some((k) => k.role === role && k.state === "active")) this.keys.push(this.key(role, algorithm));
        }
        this.serial = zone.soa_serial;
      } else {
        for (const k of this.keys) {
          if (k.state === "active") Object.assign(k, { state: "retired", retired: now });
        }
        this.serial = null;
      }
    }
    return route.fallback();
  }

  private status() {
    const zone = this.zone() as { id: string; dnssec?: { mode?: string } };
    const mode = zone.dnssec?.mode ?? "off";
    const signed = this.serial !== null ? new Date().toISOString() : null;
    return {
      zone: zone.id,
      mode,
      keys: this.keys,
      ds:
        mode === "online"
          ? this.keys
              .filter((k) => k.role !== "zsk" && k.state === "active")
              .map((k) => ({ type: "DS", key_tag: k.key_tag, algorithm: k.algorithm === "ed25519" ? 15 : 13, digest_type: 2, digest: this.digests.get(k.key_tag) }))
          : [],
      signed_serial: this.serial,
      last_signed: signed,
      findings: [],
    };
  }

  private async dnssec(route: Route): Promise<void> {
    const request = route.request();
    const json = (status: number, value: unknown) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
    if (request.method() === "GET") return json(200, this.status());
    const role = (JSON.parse(request.postData() ?? "{}") as { role: Key["role"] }).role;
    this.rollovers.push(role);
    const old = this.keys.find((k) => k.role === role && k.state === "active");
    const fresh = this.key(role, old?.algorithm ?? "ecdsa_p256_sha256");
    if (old) Object.assign(old, { state: "removed", retired: new Date().toISOString() });
    this.keys.push(fresh);
    const job = randomUUID();
    return route.fulfill({ status: 202, contentType: "application/json", headers: { Location: `/api/v1/jobs/${job}` }, body: JSON.stringify({ job_id: job }) });
  }
}

async function openTab(page: Page, dns: FakeDns): Promise<void> {
  const zone = dns.zone(ZONE);
  if (!zone) throw new Error("no zone");
  await page.goto(`/dns/zones/${zone.id}`);
  await expect(page.getByTestId("page-dns-zone")).toBeVisible();
  await page.getByTestId("zone-tab-dnssec").click();
  await expect(page.getByTestId("dnssec-tab")).toBeVisible();
}

test("switches signing on, shows the DS for the parent and rolls the ZSK", async ({ page, signedIn }) => {
  void signedIn;
  const dns = await FakeDns.install(page);
  const signer = await FakeSigner.install(page, dns);
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]).catch(() => undefined);
  await openTab(page, dns);
  await expect(page.getByTestId("dnssec-mode")).toHaveText("Not signed");

  await page.getByTestId("dnssec-mode-online").check();
  await page.getByTestId("dnssec-save").click();
  await expect(page.getByTestId("dnssec-mode")).toHaveText("Signed by Tenko");
  const patch = dns.sent.find((s) => s.method === "PATCH");
  expect(patch?.body).toMatchObject({ dnssec: { mode: "online", algorithm: "ecdsa_p256_sha256", denial: { kind: "nsec" }, csk: false } });

  const ksk = signer.keys.find((k) => k.role === "ksk");
  const lines = page.getByTestId("dnssec-ds-lines");
  await expect(lines).toHaveText(new RegExp(`^example\\.test\\. IN DS ${ksk?.key_tag} 13 2 [0-9A-F]{64}$`));
  await expect(page.getByTestId("dnssec-key")).toHaveCount(2);
  await expect(page.locator('[data-testid="dnssec-key"][data-state="active"]')).toHaveCount(2);
  await page.getByTestId("dnssec-ds-copy").click();

  const zsk = signer.keys.find((k) => k.role === "zsk")?.key_tag;
  await page.getByTestId("dnssec-roll-zsk").click();
  await expect(page.locator(`[data-testid="dnssec-key"][data-key="zsk-${zsk}"]`)).toHaveCount(0);
  await expect(page.locator('[data-testid="dnssec-key"][data-key^="zsk-"]')).toHaveCount(1);
  expect(signer.rollovers).toEqual(["zsk"]);
});

test("shows the state to a viewer without controls", async ({ page, api, signedIn }) => {
  void signedIn;
  const dns = await FakeDns.install(page);
  await FakeSigner.install(page, dns);
  await signInAsViewer(api);
  await openTab(page, dns);
  await expect(page.getByTestId("dnssec-mode")).toHaveText("Not signed");
  await expect(page.getByTestId("dnssec-save")).toHaveCount(0);
  await expect(page.getByTestId("dnssec-mode-online")).toBeDisabled();
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the DNSSEC tab of a signed zone in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    const dns = await FakeDns.install(page);
    await FakeSigner.install(page, dns);
    await openTab(page, dns);
    await page.getByTestId("dnssec-mode-online").check();
    await page.getByTestId("dnssec-save").click();
    await expect(page.getByTestId("dnssec-mode")).toHaveText("Signeras av Tenko");
    await expectRendered(page, page.getByTestId("dnssec-tab"), "sv", testInfo, "dns-dnssec");
  });
});
