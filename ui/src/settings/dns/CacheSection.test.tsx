// The cache section of the DNS settings page: nothing is read until asked, the entries in name
// order with their TTL, view, stale flag, hits and data, the suffix filter and its check,
// paging by cursor, the flush of a suffix after a confirmation, the audit of every read, a
// failed read, Swedish, and no accessibility violations.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { audit } from "../../api/mock/audit-store";
import { CACHE_VIEW } from "../../api/mock/dns-cache-model";
import { server } from "../../api/mock/node";
import { dnsCacheState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import DnsSettingsPage from "./DnsSettingsPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

function open() {
  return renderRoute(DnsSettingsPage, { url: "/settings/dns", path: "/settings/dns" });
}

async function section(): Promise<HTMLElement> {
  return screen.findByTestId("dns-cache");
}

function rows(): HTMLElement[] {
  return screen.queryAllByTestId("dns-cache-row");
}

function keys(): string[] {
  return rows().map((r) => `${r.dataset.key} ${r.dataset.type}`);
}

function suffix(text: string) {
  fireEvent.input(screen.getByTestId("field-cache-suffix"), { target: { value: text } });
}

function show() {
  fireEvent.submit(screen.getByTestId("dns-cache-form"));
}

function reads() {
  return audit.records.filter((r) => r.draft.action === "dns.cache.read");
}

describe("the cache section", () => {
  it("reads nothing until asked, then lists the entries in name order", async () => {
    open();
    const cache = await section();
    expect(cache.textContent).toContain("recorded in the audit log");
    expect(screen.queryByTestId("dns-cache-table")).toBeNull();
    expect(reads()).toHaveLength(0);
    show();
    await waitFor(() => expect(rows().length).toBe(7));
    expect(keys()).toEqual([
      "example.net TXT",
      "ns1.example.org AAAA",
      "example.test MX",
      "intranet.example.test A",
      "missing.example.test A",
      "www.example.test A",
      "www.example.test AAAA",
    ]);
    expect(reads()).toHaveLength(1);
    expect(reads()[0]?.draft.details?.context).toMatchObject({ from_cursor: "first", to_cursor: "end", entries: "7" });
  });

  it("shows the TTL left, the view, the stale flag, the hits and the data of each entry", async () => {
    open();
    await section();
    show();
    await waitFor(() => expect(rows().length).toBe(7));
    const cells = (key: string, type: string) => {
      const row = rows().find((r) => r.dataset.key === key && r.dataset.type === type);
      if (!row) throw new Error(`no row ${key} ${type}`);
      return within(row).getAllByRole("cell").map((c) => c.textContent);
    };
    expect(cells("www.example.test", "A")).toEqual(["www.example.test", "A", "4 min", "Default", "Secure", "", "41", "CNAME cdn.example.test, 192.0.2.80"]);
    expect(cells("example.test", "MX")).toEqual(["example.test", "MX", "56 min", "Default", "Unvalidated", "", "3", "10 mail.example.test"]);
    expect(cells("example.net", "TXT")[2]).toBe("3 h");
    expect(cells("intranet.example.test", "A")[3]).toBe(CACHE_VIEW);
    expect(cells("missing.example.test", "A")).toEqual(["missing.example.test", "A", "–", "Default", "Unvalidated", "Stale", "0", "NXDOMAIN"]);
    expect(cells("ns1.example.org", "AAAA")[7]).toBe("NODATA");
    expect(screen.getAllByTestId("dns-cache-stale")).toHaveLength(1);
  });

  it("shows the validation state of each entry and the extended error code of a bogus one", async () => {
    open();
    await section();
    show();
    await waitFor(() => expect(rows().length).toBe(7));
    const state = (key: string, type: string) => {
      const row = rows().find((r) => r.dataset.key === key && r.dataset.type === type);
      return within(row as HTMLElement).getByTestId("dns-cache-state");
    };
    expect(state("www.example.test", "A").dataset.state).toBe("secure");
    expect(state("www.example.test", "A").querySelector(".tag")?.getAttribute("title")).toContain("Signatures valid until");
    expect(within(state("www.example.test", "A")).queryByTestId("dns-cache-ede")).toBeNull();
    expect(state("example.net", "TXT").dataset.state).toBe("unvalidated");
    expect(state("ns1.example.org", "AAAA").dataset.state).toBe("bogus");
    expect(within(state("ns1.example.org", "AAAA")).getByTestId("dns-cache-ede").textContent).toBe("EDE 6");
    expect(screen.getAllByTestId("dns-cache-ede")).toHaveLength(1);
  });

  it("narrows the listing to a suffix and checks it first", async () => {
    open();
    await section();
    suffix("not a name");
    show();
    expect((await screen.findByTestId("field-error")).dataset.field).toBe("suffix");
    expect(reads()).toHaveLength(0);
    suffix("Example.Test.");
    show();
    await waitFor(() => expect(rows().length).toBe(5));
    expect(rows().every((r) => r.dataset.key?.endsWith("example.test"))).toBe(true);
    expect(screen.queryByTestId("field-error")).toBeNull();
    expect(reads().at(-1)?.draft.details?.context).toMatchObject({ "filter.suffix": "example.test" });
    suffix("nothing.example.test");
    show();
    expect((await screen.findByTestId("dns-cache-empty")).textContent).toContain("No entries for nothing.example.test");
  });

  it("pages through the cursor", async () => {
    const state = dnsCacheState();
    const template = state.entries[0]!;
    state.entries = Array.from({ length: 130 }, (_, n) => ({ ...template, name: `h${String(n).padStart(3, "0")}.example.test` }));
    open();
    await section();
    show();
    await waitFor(() => expect(rows().length).toBe(100));
    expect(screen.getByTestId("dns-cache-paging").dataset.page).toBe("1");
    expect((screen.getByTestId("dns-cache-previous") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId("dns-cache-next"));
    await waitFor(() => expect(rows().length).toBe(30));
    expect(rows()[0]?.dataset.key).toBe("h100.example.test");
    expect(screen.getByTestId("dns-cache-paging").dataset.page).toBe("2");
    expect((screen.getByTestId("dns-cache-next") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId("dns-cache-previous"));
    await waitFor(() => expect(rows().length).toBe(100));
    expect(reads().map((r) => r.draft.details?.context?.from_cursor)).toEqual(["first", "p100", "first"]);
  });

  it("flushes the suffix shown after a confirmation and reads again", async () => {
    open();
    await section();
    expect(screen.queryByTestId("dns-cache-flush")).toBeNull();
    suffix("www.example.test");
    show();
    await waitFor(() => expect(rows().length).toBe(2));
    const flush = screen.getByTestId("dns-cache-flush");
    expect(flush.textContent).toBe("Flush www.example.test");
    fireEvent.click(flush);
    const dialog = await screen.findByTestId("dns-cache-flush-dialog");
    expect(dialog.textContent).toContain("Flush www.example.test from the cache?");
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dns-cache-flush-dialog")).toBeNull());
    expect(dnsCacheState().entries).toHaveLength(7);
    fireEvent.click(screen.getByTestId("dns-cache-flush"));
    fireEvent.click(within(await screen.findByTestId("dns-cache-flush-dialog")).getByTestId("confirm-ok"));
    expect(await screen.findByTestId("dns-cache-empty")).toBeTruthy();
    expect(dnsCacheState().entries).toHaveLength(5);
    const flushes = audit.records.filter((r) => r.draft.action === "dns.cache.flush");
    expect(flushes.at(-1)?.draft.details?.context).toMatchObject({ detail: "2 cache entr(ies) at or below www.example.test removed" });
  });

  it("shows a failed read", async () => {
    server.use(
      http.get("/api/v1/nodes/:id/dns/cache", () =>
        HttpResponse.json(
          { type: "about:blank", status: 500, code: "sys.internal", title: "Internal error", detail: "Internal error", params: {} },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    const cache = await section();
    show();
    expect(await within(cache).findByRole("alert")).toBeTruthy();
    expect(screen.queryByTestId("dns-cache-table")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    const cache = await section();
    expect(within(cache).getByRole("heading", { level: 2 }).textContent).toBe("Vad cachen innehåller");
    show();
    await waitFor(() => expect(rows().length).toBe(7));
    expect(screen.getByTestId("dns-cache-stale").textContent).toBe("Inaktuell");
  });

  it("has no accessibility violations", async () => {
    const { container } = open();
    await section();
    suffix("example.test");
    show();
    await waitFor(() => expect(rows().length).toBe(5));
    expect(await axeViolations(container)).toEqual([]);
  });
});
