// The zone file import: a pasted or chosen file, the preview of the dry run (counts, records
// per type, losses), the apply as a job followed to its report, a file that does not parse,
// and the import of what the export wrote.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DNS_IDS, exportZoneFile } from "../api/mock/dns-model";
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
    await waitFor(() => expect(screen.getByTestId("import-result").dataset.state).toBe("done"), { timeout: 4000 });
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
