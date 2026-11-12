// The zone file import: a pasted or chosen file, the preview of the dry run (counts, records
// per type, losses), the apply as a job followed to its report, a file that does not parse,
// the import of what the export wrote, and the claimable names of a Windows export: the listing
// with its pages, the rule, the names that stay static, the approval and the answer when the
// set changed since the preview.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DNS_IDS, exportZoneFile, type DnsRrSet } from "../api/mock/dns-model";
import { server } from "../api/mock/node";
import { dnsState } from "../api/mock/routes-dns";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import ImportWizard from "./ImportWizard";
import { dnsNotBuilt, recordWrites } from "./testkit";

const ZONE = DNS_IDS.zone.example;

const FILE = [
  "$ORIGIN example.test.",
  "$TTL 1800",
  "@        IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )",
  "printer  IN A    192.0.2.30",
  "         IN A    192.0.2.31",
  "www      600 IN A 192.0.2.80",
  "wiki     IN CNAME www",
  "legacy   IN HINFO \"pc\" \"os\"",
  "",
].join("\n");

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

function open() {
  return renderRoute(ImportWizard, { url: `/dns/import/${ZONE}`, path: "/dns/import/:id" });
}

async function paste(text: string) {
  const area = await screen.findByTestId("field-zone_file");
  fireEvent.input(area, { target: { value: text } });
}

const step = () => screen.getAllByTestId("import-step").find((s) => s.getAttribute("aria-current") === "step")?.dataset.key;

describe("the zone file import", () => {
  it("previews a file, applies it as a job and shows the report", async () => {
    const writes = recordWrites();
    const view = open();
    await screen.findByText("example.test", { selector: ".sub" });
    await paste(FILE);
    fireEvent.click(screen.getByTestId("import-preview"));
    const report = await screen.findByTestId("import-preview-report");
    expect(step()).toBe("preview");
    const facts = Object.fromEntries(within(report).getAllByTestId("import-fact").map((f) => [f.dataset.key, f.dataset.count]));
    expect(facts).toEqual({ added: "2", replaced: "1", removed: "0" });
    const types = within(report).getAllByTestId("import-type").map((r) => [r.dataset.key, r.dataset.count]);
    expect(types).toEqual([
      ["A", "3"],
      ["CNAME", "1"],
    ]);
    expect(within(report).getAllByTestId("import-loss").map((l) => l.dataset.code)).toEqual(["dns.import.soa", "dns.import.unsupported_type"]);
    expect(within(report).getByText("A record of a type that is not supported was skipped.")).toBeTruthy();
    // The dry run wrote nothing.
    expect(dnsState().rrsets.get(ZONE)?.some((s) => s.name === "printer.example.test")).toBe(false);
    expect(await axeViolations(view.container)).toEqual([]);

    fireEvent.click(within(report).getByTestId("import-apply"));
    // The job runs, then the result replaces the progress.
    await waitFor(() => expect(screen.getByTestId("import-result").dataset.state).toBe("done"), { timeout: 30_000 });
    const result = screen.getByTestId("import-result");
    const serial = String(dnsState().zones.find((z) => z.id === ZONE)?.soa_serial);
    expect(within(result).getByTestId("import-serial").dataset.key).toBe(serial);
    expect(within(result).getByTestId("import-open-job").getAttribute("href")).toMatch(/^\/jobs\//);
    expect(dnsState().rrsets.get(ZONE)?.find((s) => s.name === "printer.example.test")?.records).toHaveLength(2);
    const sent = writes().filter((w) => w.url.includes("/records/import"));
    expect(sent.map((w) => w.url.includes("dry_run=true"))).toEqual([true, false]);
    expect(sent[1]?.body).toEqual({ zone_file: FILE, replace: false });
  });

  it("says on which line a file does not parse", async () => {
    open();
    await paste("$INCLUDE other.zone\n");
    fireEvent.click(screen.getByTestId("import-preview"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dns.zonefile.invalid");
    expect(notice.textContent).toContain("line 1");
    expect(step()).toBe("upload");
  });

  it("imports what the export wrote without a change", async () => {
    open();
    await paste(exportZoneFile(dnsState(), ZONE));
    fireEvent.click(screen.getByTestId("import-preview"));
    const report = await screen.findByTestId("import-preview-report");
    const facts = Object.fromEntries(within(report).getAllByTestId("import-fact").map((f) => [f.dataset.key, f.dataset.count]));
    expect(facts).toEqual({ added: "0", replaced: "0", removed: "0" });
  });

  it("reads a chosen file", async () => {
    open();
    const input = (await screen.findByTestId("import-file-input")) as HTMLInputElement;
    const file = new File([FILE], "example.test.zone", { type: "text/plain" });
    fireEvent.change(input, { target: { files: [file] } });
    expect((await screen.findByTestId("import-file")).dataset.key).toBe("example.test.zone");
    await waitFor(() => expect((screen.getByTestId("field-zone_file") as HTMLTextAreaElement).value).toBe(FILE));
  });

  it("says the DNS service is not built yet when the server answers 501", async () => {
    dnsNotBuilt();
    open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    expect(screen.queryByTestId("import-upload")).toBeNull();
  });
});

// The Windows dialect: a file written by `dnscmd /ZoneExport`. Records with an aging mark are
// candidates to be claimable by their host, static ones stay manual, WINS records are losses.
const WINDOWS_FILE = [
  "$ORIGIN example.test.",
  "@        3600 IN SOA ns1 hostmaster ( 1 3600 900 1209600 300 )",
  "pc07     [AGE:3612345] 1200 IN A 192.0.2.77",
  "pc08     [AGE:3612399] 1200 IN A 192.0.2.78",
  "fileserv 3600 IN A 192.0.2.79",
  "@        0 IN WINS 192.0.2.10",
  "",
].join("\n");

/** A Windows file with a name that cannot become claimable (wpad) beside two that can. */
const WITH_WPAD = [WINDOWS_FILE, "wpad     [AGE:3612399] 1200 IN A 192.0.2.7", ""].join("\n");

const importCalls = (writes: ReturnType<typeof recordWrites>) => writes().filter((w) => w.url.includes("/records/import"));
const originOf = (name: string) => dnsState().rrsets.get(ZONE)?.find((s) => s.name === name)?.origin;

async function previewWindows(file: string) {
  open();
  await paste(file);
  fireEvent.click(await screen.findByTestId("field-dialect-windows"));
  fireEvent.click(screen.getByTestId("import-preview"));
  return screen.findByTestId("import-preview-report");
}

const approval = () => screen.getByTestId("field-claim-approve") as HTMLInputElement;
const claimKeys = () => screen.queryAllByTestId("import-claim-row").map((r) => r.dataset.key);
const finished = () => waitFor(() => expect(screen.getByTestId("import-result").dataset.state).toBe("done"), { timeout: 30_000 });

describe("the dialect of the file", () => {
  it("offers the zone file and the Windows export, with what the Windows one does", async () => {
    open();
    const group = await screen.findByTestId("import-dialect");
    expect((within(group).getByTestId("field-dialect-rfc1035") as HTMLInputElement).checked).toBe(true);
    expect(within(group).getByTestId("import-dialect-help").textContent).toContain("standard master file");
    fireEvent.click(within(group).getByTestId("field-dialect-windows"));
    expect(within(group).getByText("Windows DNS export (dnscmd /ZoneExport)")).toBeTruthy();
    expect(within(group).getByTestId("import-dialect-help").textContent).toContain("aging mark are imported as claimable by their host");
    expect(within(group).getByTestId("import-dialect-help").textContent).toContain("static records stay manual");
  });

  it("does not send a dialect for a plain zone file and shows no claimable section", async () => {
    const writes = recordWrites();
    open();
    await paste(FILE);
    fireEvent.click(screen.getByTestId("import-preview"));
    const report = await screen.findByTestId("import-preview-report");
    expect(within(report).queryByTestId("import-claim")).toBeNull();
    expect(within(report).queryByTestId("import-claimable")).toBeNull();
    expect(importCalls(writes)[0]?.body).not.toHaveProperty("dialect");
    expect(importCalls(writes)[0]?.body).not.toHaveProperty("claimable");
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    const group = await screen.findByTestId("import-dialect");
    fireEvent.click(within(group).getByTestId("field-dialect-windows"));
    expect(within(group).getByTestId("import-dialect-help").textContent).toContain("åldringsmarkering");
  });
});

describe("the names a Windows file makes claimable", () => {
  it("lists them with their computer account and the reasons the others stay static", async () => {
    const view = open();
    await paste(WITH_WPAD);
    fireEvent.click(await screen.findByTestId("field-dialect-windows"));
    fireEvent.click(screen.getByTestId("import-preview"));
    const report = await screen.findByTestId("import-preview-report");
    const section = within(report).getByTestId("import-claim");
    expect(within(section).getByTestId("import-claim-count").dataset.count).toBe("2");
    expect(within(section).getByTestId("import-claim-count").textContent).toBe("2 names become claimable");
    expect(claimKeys()).toEqual(["pc07.example.test/A", "pc08.example.test/A"]);
    const first = within(section).getAllByTestId("import-claim-row")[0] as HTMLElement;
    expect(first.dataset.claimant).toBe("PC07$");
    expect(first.textContent).toContain("192.0.2.77");
    expect(within(section).getByTestId("import-claim-paging").textContent).toContain("Showing 2 of 2");
    expect(within(section).queryByTestId("import-claim-more")).toBeNull();
    // The name that cannot become claimable is listed with its reason in words.
    expect(within(section).getByTestId("import-held-count").dataset.count).toBe("1");
    const held = within(section).getByTestId("import-held-row");
    expect([held.dataset.key, held.dataset.reason]).toEqual(["wpad.example.test/A", "service_name"]);
    expect(held.textContent).toContain("A name clients use to find a service (wpad, isatap)");
    expect(within(section).queryByTestId("import-held-more")).toBeNull();
    // The approval is off by default, and says what happens without it.
    expect(approval().checked).toBe(false);
    expect(approval().disabled).toBe(false);
    expect(section.textContent).toContain("Make these 2 names claimable by the computers they name");
    expect(within(section).getByTestId("import-approve-help").textContent).toContain("imported static");
    expect(within(report).getAllByTestId("import-loss").map((l) => l.dataset.code)).toContain("dns.zonefile.wins");
    expect(within(report).getByText("WINS records are not kept.")).toBeTruthy();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("imports the names static when the approval stays off, and says so", async () => {
    const writes = recordWrites();
    const report = await previewWindows(WITH_WPAD);
    fireEvent.click(within(report).getByTestId("import-apply"));
    await finished();
    const sent = importCalls(writes);
    expect(sent.map((w) => w.body?.dialect)).toEqual(["windows", "windows"]);
    expect(sent[1]?.body).not.toHaveProperty("claimable");
    expect(originOf("pc07.example.test")).toBe("manual");
    expect(originOf("fileserv.example.test")).toBe("manual");
    const result = screen.getByTestId("import-result");
    expect(within(result).queryByTestId("import-claimable")).toBeNull();
    // Three names stay static: the two that were not approved and wpad.
    expect(within(result).getByTestId("import-held-count").dataset.count).toBe("3");
    const reasons = Object.fromEntries(within(result).getAllByTestId("import-held-row").map((r) => [r.dataset.key, r.dataset.reason]));
    expect(reasons).toEqual({ "pc07.example.test/A": "not_approved", "pc08.example.test/A": "not_approved", "wpad.example.test/A": "service_name" });
  });

  it("sends the digest of the preview with the approval and makes the names claimable", async () => {
    const writes = recordWrites();
    const report = await previewWindows(WITH_WPAD);
    fireEvent.click(approval());
    expect(approval().checked).toBe(true);
    fireEvent.click(within(report).getByTestId("import-apply"));
    await finished();
    const sent = importCalls(writes);
    expect(sent[1]?.body?.claimable).toEqual({ approve: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(originOf("pc07.example.test")).toBe("ad");
    expect(originOf("pc08.example.test")).toBe("ad");
    expect(originOf("fileserv.example.test")).toBe("manual");
    expect(originOf("wpad.example.test")).toBe("manual");
    const result = screen.getByTestId("import-result");
    expect(within(result).getByTestId("import-claimable").dataset.count).toBe("2");
    expect(within(result).getByTestId("import-claimable").textContent).toBe("2 names were made claimable by their computers");
    expect(within(result).getByTestId("import-held-count").dataset.count).toBe("1");
  });

  it("sends the rule with the preview and with the import, and the digest follows the rule", async () => {
    const writes = recordWrites();
    const report = await previewWindows(WITH_WPAD);
    const calls = importCalls(writes).length;
    fireEvent.input(screen.getByTestId("field-claim-except"), { target: { value: "pc08.example.test, fileserv.example.test" } });
    // The fields hold a rule the preview was not made with: nothing can be approved yet.
    expect(screen.getByTestId("import-rule-dirty")).toBeTruthy();
    expect(approval().disabled).toBe(true);
    fireEvent.click(screen.getByTestId("import-rule-apply"));
    await waitFor(() => expect(importCalls(writes)).toHaveLength(calls + 1));
    await waitFor(() => expect(claimKeys()).toEqual(["pc07.example.test/A"]));
    expect(screen.queryByTestId("import-rule-dirty")).toBeNull();
    expect(Object.fromEntries(screen.getAllByTestId("import-held-row").map((r) => [r.dataset.key, r.dataset.reason]))).toEqual({
      "pc08.example.test/A": "rule",
      "wpad.example.test/A": "service_name",
    });
    expect(importCalls(writes)[1]?.body?.claimable).toEqual({ except: ["pc08.example.test", "fileserv.example.test"] });
    fireEvent.click(approval());
    fireEvent.click(within(report).getByTestId("import-apply"));
    await finished();
    expect(importCalls(writes)[2]?.body?.claimable).toEqual({
      except: ["pc08.example.test", "fileserv.example.test"],
      approve: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(originOf("pc07.example.test")).toBe("ad");
    expect(originOf("pc08.example.test")).toBe("manual");
  });

  it("takes the approval back when the rule changes, and when the file is previewed again", async () => {
    const report = await previewWindows(WITH_WPAD);
    fireEvent.click(approval());
    expect(approval().checked).toBe(true);
    fireEvent.input(screen.getByTestId("field-claim-under"), { target: { value: "lab.example.test" } });
    expect(approval().checked).toBe(false);
    expect(approval().disabled).toBe(true);
    // Back to the file, a change of it, and a new preview: the approval starts unchecked.
    fireEvent.input(screen.getByTestId("field-claim-under"), { target: { value: "" } });
    fireEvent.click(approval());
    expect(approval().checked).toBe(true);
    fireEvent.click(within(report).getByTestId("import-back"));
    await paste(`${WITH_WPAD}pc09     [AGE:1] 1200 IN A 192.0.2.80\n`);
    fireEvent.click(screen.getByTestId("import-preview"));
    await screen.findByTestId("import-preview-report");
    await waitFor(() => expect(claimKeys()).toHaveLength(3));
    expect(approval().checked).toBe(false);
  });

  it("returns to the preview with a message when the set changed since the preview", async () => {
    const writes = recordWrites();
    const report = await previewWindows(WITH_WPAD);
    fireEvent.click(approval());
    // Another writer gives pc07 a TXT record: the name holds other data now.
    const seed = dnsState().rrsets.get(ZONE)?.[0] as DnsRrSet;
    dnsState().rrsets.get(ZONE)?.push({ ...seed, name: "pc07.example.test", type: "TXT", records: [{ type: "TXT", strings: ["x"] }] });
    fireEvent.click(within(report).getByTestId("import-apply"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dns.import.claimable_changed");
    expect(notice.textContent).toContain("Run the preview again");
    expect(step()).toBe("preview");
    expect(approval().checked).toBe(false);
    expect(approval().disabled).toBe(true);
    expect(claimKeys()).toEqual([]);
    expect(originOf("pc08.example.test")).toBeUndefined();
    // Previewing again shows the set as it is now, and the approval can be given anew.
    fireEvent.click(screen.getByTestId("import-rule-apply"));
    await waitFor(() => expect(claimKeys()).toEqual(["pc08.example.test/A"]));
    expect(screen.queryByTestId("error-notice")).toBeNull();
    expect(approval().disabled).toBe(false);
    expect(importCalls(writes).map((w) => w.url.includes("dry_run=true"))).toEqual([true, false, true]);
  });

  describe("with a long listing", () => {
    const many = (count: number) => Array.from({ length: count }, (_, i) => `h${String(i).padStart(4, "0")} [AGE:1] 1200 IN A 192.0.2.${(i % 250) + 1}`).join("\n");

    it("shows more of it on request and appends the page", async () => {
      const writes = recordWrites();
      await previewWindows(many(1200));
      expect(claimKeys()).toHaveLength(1000);
      expect(screen.getByTestId("import-claim-paging").textContent).toContain("Showing 1,000 of 1,200");
      // The approval covers every name: it waits until the whole list is shown.
      expect(approval().disabled).toBe(true);
      expect(screen.getByTestId("import-approve-whole")).toBeTruthy();
      fireEvent.click(screen.getByTestId("import-claim-more"));
      await waitFor(() => expect(claimKeys()).toHaveLength(1200));
      expect(claimKeys().slice(998, 1002)).toEqual(["h0998.example.test/A", "h0999.example.test/A", "h1000.example.test/A", "h1001.example.test/A"]);
      expect(screen.getByTestId("import-claim-paging").textContent).toContain("Showing 1,200 of 1,200");
      expect(screen.queryByTestId("import-claim-more")).toBeNull();
      const pages = importCalls(writes).map((w) => w.body?.claimable);
      expect(pages).toEqual([undefined, { after: "h0999.example.test/A", limit: 5000 }]);
      expect(approval().disabled).toBe(false);
    });

    it("discards the list and asks for a new preview when a later page has another digest", async () => {
      await previewWindows(many(1200));
      fireEvent.click(approval());
      // A name of the first page now holds other data: the later page has another digest.
      const seed = dnsState().rrsets.get(ZONE)?.[0] as DnsRrSet;
      dnsState().rrsets.get(ZONE)?.push({ ...seed, name: "h0001.example.test", type: "TXT", records: [{ type: "TXT", strings: ["x"] }] });
      fireEvent.click(screen.getByTestId("import-claim-more"));
      expect(await screen.findByTestId("import-claim-stale")).toBeTruthy();
      expect(claimKeys()).toEqual([]);
      expect(approval().checked).toBe(false);
      expect(approval().disabled).toBe(true);
      fireEvent.click(screen.getByTestId("import-rule-apply"));
      await waitFor(() => expect(claimKeys()).toHaveLength(1000));
      expect(screen.queryByTestId("import-claim-stale")).toBeNull();
      expect(screen.getByTestId("import-claim-count").dataset.count).toBe("1199");
    });
  });

  describe("with an answer the mock does not give", () => {
    const answer = (extra: Record<string, unknown>) =>
      server.use(
        http.post("/api/v1/dns/zones/:id/records/import", () =>
          HttpResponse.json({ added: 0, replaced: 0, removed: 0, losses: [], types: [], dry_run: true, ...extra }),
        ),
      );

    it("warns when the file has too many candidates and offers no approval", async () => {
      answer({
        claimable: 0,
        claimable_overflow: true,
        held_back: 1500,
        held_back_names: [{ name: "h1.example.test", rtype: "A", line: 1, reason: "too_many" }],
      });
      const report = await previewWindows(WINDOWS_FILE);
      expect(within(report).getByTestId("import-claim-overflow").textContent).toContain("more than 250,000 records with an aging mark");
      expect(approval().disabled).toBe(true);
      expect(approval().checked).toBe(false);
      expect(within(report).getByTestId("import-held-row").textContent).toContain("More names than one import can make claimable");
      expect(within(report).getByTestId("import-held-more").dataset.count).toBe("1499");
      expect(within(report).getByTestId("import-held-more").textContent).toBe("and 1,499 more");
    });

    it("offers no approval when no name qualifies", async () => {
      answer({ claimable: 0, claimable_digest: "0".repeat(64), claimable_names: [] });
      await previewWindows(WINDOWS_FILE);
      expect(approval().disabled).toBe(true);
      expect(screen.getByTestId("import-approve-help").textContent).toContain("nothing to approve");
      expect(screen.queryByTestId("import-claim-names")).toBeNull();
    });
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    const report = await previewWindows(WITH_WPAD);
    expect(within(report).getByTestId("import-claim-count").textContent).toBe("2 namn kan tas över av sin värd");
    expect(within(report).getByTestId("import-held-row").textContent).toContain("Ett namn som klienter använder för att hitta en tjänst");
    expect(within(report).getByTestId("import-claim").textContent).toContain("Låt datorerna som namnen tillhör ta över dessa 2 namn");
    expect(within(report).getByTestId("import-approve-help").textContent).toContain("importeras posterna som statiska");
  });
});
