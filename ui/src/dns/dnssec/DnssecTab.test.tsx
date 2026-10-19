// The DNSSEC tab of the zone page (WP6.3): signing switched on through the zone's policy, the
// DS records for the parent with the copy button, the keys with their states, the rollover with
// its job, the gating of the controls, signing switched off, and the notice of a server
// without the DNS service.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DNS_IDS } from "../../api/mock/dns-model";
import { dnssecState, dnsState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { dnsNotBuilt } from "../testkit";
import ZonePage from "../ZonePage";
import { dsLines } from "./api";

const ZONE = DNS_IDS.zone.example;

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
  vi.restoreAllMocks();
});

function open() {
  return renderRoute(ZonePage, { url: `/dns/zones/${ZONE}/dnssec`, path: "/dns/zones/:id/:tab?", routes: { "/dns": () => <div data-testid="zones-page" /> } });
}

async function enable(options: { csk?: boolean; nsec3?: boolean } = {}) {
  const tab = await screen.findByTestId("dnssec-tab");
  await waitFor(() => expect(within(tab).getByTestId("dnssec-mode").textContent).toBe("Not signed"));
  fireEvent.click(screen.getByTestId("dnssec-mode-online"));
  if (options.nsec3) fireEvent.click(screen.getByTestId("dnssec-nsec3"));
  if (options.csk) fireEvent.click(screen.getByTestId("dnssec-csk"));
  fireEvent.click(screen.getByTestId("dnssec-save"));
  await waitFor(() => expect(screen.getByTestId("dnssec-mode").textContent).toBe("Signed by Tenko"));
}

const zone = () => dnsState().zones.find((z) => z.id === ZONE);

describe("the DNSSEC tab", () => {
  it("shows an unsigned zone and signs it through the policy", async () => {
    const view = open();
    await enable();
    expect(zone()?.dnssec?.mode).toBe("online");
    const keys = await screen.findAllByTestId("dnssec-key");
    expect(keys.map((k) => k.dataset.key?.split("-")[0])).toEqual(["ksk", "zsk"]);
    expect(keys.every((k) => k.dataset.state === "active")).toBe(true);
    const lines = screen.getByTestId("dnssec-ds-lines").textContent ?? "";
    expect(lines).toMatch(/^example\.test\. IN DS \d+ 13 2 [0-9A-F]{64}$/);
    expect(screen.getByTestId("dnssec-signed-serial").textContent).not.toBe("–");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("copies the DS records for the parent", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    open();
    await enable();
    fireEvent.click(await screen.findByTestId("dnssec-ds-copy"));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(writeText.mock.calls[0]?.[0]).toBe(screen.getByTestId("dnssec-ds-lines").textContent);
  });

  it("signs with one combined key and NSEC3 when asked", async () => {
    open();
    await enable({ csk: true, nsec3: true });
    expect(zone()?.dnssec?.csk).toBe(true);
    expect(zone()?.dnssec?.denial).toEqual({ kind: "nsec3", iterations: 0, salt: "" });
    const keys = await screen.findAllByTestId("dnssec-key");
    expect(keys.map((k) => k.dataset.key?.split("-")[0])).toEqual(["csk"]);
    expect(screen.getByTestId("dnssec-roll-csk")).toBeTruthy();
    expect(screen.queryByTestId("dnssec-roll-zsk")).toBeNull();
  });

  it("starts a ZSK rollover and shows the new key", async () => {
    open();
    await enable();
    const before = (await screen.findAllByTestId("dnssec-key")).find((k) => k.dataset.key?.startsWith("zsk"))?.dataset.key;
    fireEvent.click(screen.getByTestId("dnssec-roll-zsk"));
    await waitFor(() => {
      const zsk = screen.getAllByTestId("dnssec-key").filter((k) => k.dataset.key?.startsWith("zsk"));
      expect(zsk).toHaveLength(1);
      expect(zsk[0]?.dataset.key).not.toBe(before);
    });
    const entry = dnssecState().get(ZONE);
    expect(entry?.keys.filter((k) => k.state === "removed").map((k) => `zsk-${k.key_tag}`)).toEqual([before]);
  });

  it("shows the running rollover with its job", async () => {
    open();
    await enable();
    const entry = dnssecState().get(ZONE);
    if (entry) entry.rollover_job = "0192a000-0000-7000-8000-000000000001";
    fireEvent.click(screen.getByTestId("zone-tab-records"));
    fireEvent.click(await screen.findByTestId("zone-tab-dnssec"));
    const link = await screen.findByTestId("dnssec-rollover-job");
    expect(link.getAttribute("href")).toBe("/jobs/0192a000-0000-7000-8000-000000000001");
    expect(screen.queryByTestId("dnssec-roll-zsk")).toBeNull();
  });

  it("unsigns the zone and keeps the keys retired", async () => {
    open();
    await enable();
    fireEvent.click(screen.getByTestId("dnssec-mode-off"));
    fireEvent.click(screen.getByTestId("dnssec-save"));
    await waitFor(() => expect(screen.getByTestId("dnssec-mode").textContent).toBe("Not signed"));
    expect(screen.queryByTestId("dnssec-ds")).toBeNull();
    const keys = await screen.findAllByTestId("dnssec-key");
    expect(keys.every((k) => k.dataset.state === "retired")).toBe(true);
  });

  it("lets a viewer read the state and offers no controls", async () => {
    await signInWithRoles(["viewer"]);
    open();
    const tab = await screen.findByTestId("dnssec-tab");
    await waitFor(() => expect(within(tab).getByTestId("dnssec-mode").textContent).toBe("Not signed"));
    expect(screen.queryByTestId("dnssec-save")).toBeNull();
    expect((screen.getByTestId("dnssec-mode-online") as HTMLInputElement).closest("fieldset")?.disabled).toBe(true);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    const tab = await screen.findByTestId("dnssec-tab");
    await waitFor(() => expect(within(tab).getByTestId("dnssec-mode").textContent).toBe("Osignerad"));
    expect(screen.getByTestId("zone-tab-dnssec").textContent).toBe("DNSSEC");
  });

  it("shows the notice of a server without the DNS service", async () => {
    dnsNotBuilt();
    open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
  });
});

describe("the DS lines", () => {
  it("are the parent's presentation form in upper-case hexadecimal", () => {
    expect(
      dsLines("example.test", {
        ds: [{ type: "DS", key_tag: 2371, algorithm: 13, digest_type: 2, digest: "ab01" }, { type: "A", address: "192.0.2.1" }],
      }),
    ).toEqual(["example.test. IN DS 2371 13 2 AB01"]);
  });
});
