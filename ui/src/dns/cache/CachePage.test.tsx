// The cache page of the DNS area (/dns/cache): nothing is read until asked, the tree of names
// built from the entries with the root expanded, expansion and selection with the mouse and the
// keyboard, the path to a suffix expanded and its folder selected, the "(same as parent folder)"
// rows, the signatures as rows of their own, the folder rows that open their folder, the cap of
// a read and the windows of the panes, no read on expand or select, the flush of a suffix after
// a confirmation, a failed read, Swedish, and no accessibility violations.
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
import { dnsNotBuilt } from "../testkit";
import CachePage from "./CachePage";

/** Every request to the listing route, with its query: each one the server would audit. */
let requests: URLSearchParams[] = [];
const onRequest = ({ request }: { request: Request }) => {
  const url = new URL(request.url);
  if (request.method === "GET" && /\/dns\/cache$/.test(url.pathname)) requests.push(url.searchParams);
};

beforeEach(async () => {
  await signInAlex();
  requests = [];
  server.events.on("request:start", onRequest);
});

afterEach(async () => {
  server.events.removeListener("request:start", onRequest);
  setSessionForTest(null);
  await setLocale("en");
});

function open() {
  return renderRoute(CachePage, { url: "/dns/cache", path: "/dns/cache" });
}

async function section(): Promise<HTMLElement> {
  return screen.findByTestId("dns-cache");
}

function tree(): HTMLElement {
  return screen.getByTestId("dns-cache-tree");
}

/** The folders shown in the tree, by name. */
function folders(): string[] {
  return screen.queryAllByTestId("dns-cache-node").map((n) => n.dataset.key ?? "");
}

function folder(name: string): HTMLElement {
  const el = screen.queryAllByTestId("dns-cache-node").find((n) => n.dataset.key === name);
  if (!el) throw new Error(`no folder ${name}`);
  return el;
}

function selected(): string | undefined {
  return screen.queryAllByTestId("dns-cache-node").find((n) => n.getAttribute("aria-selected") === "true")?.dataset.key;
}

function rows(): HTMLElement[] {
  return screen.queryAllByTestId("dns-cache-row");
}

/** The row of an entry (or of the signature covering `covered`), by name and type. */
function row(key: string, type: string, covered?: string): HTMLElement {
  const found = rows().find((r) => r.dataset.key === key && r.dataset.type === type && (!covered || r.dataset.covered === covered));
  if (!found) throw new Error(`no row ${key} ${type}`);
  return found;
}

function folderRow(name: string): HTMLElement {
  const el = screen.queryAllByTestId("dns-cache-folder-row").find((r) => r.dataset.key === name);
  if (!el) throw new Error(`no folder row ${name}`);
  return el;
}

/** The rows of the right pane as `name type`, folders as `folder name`. */
function pane(): string[] {
  return [...screen.getByTestId("dns-cache-table").querySelectorAll("tbody tr")].map((r) => {
    const row = r as HTMLElement;
    if (row.dataset.testid === "dns-cache-folder-row") return `folder ${row.dataset.key}`;
    return `${row.dataset.own === "true" ? "(same)" : row.dataset.key} ${row.dataset.type}${row.dataset.covered ? ` ${row.dataset.covered}` : ""}`;
  });
}

function cells(row: HTMLElement): (string | null)[] {
  return within(row).getAllByRole("cell").map((c) => c.textContent);
}

function selectFolder(name: string) {
  fireEvent.click(folder(name).querySelector(".tnode") as HTMLElement);
}

function toggleFolder(name: string) {
  fireEvent.click(folder(name).querySelector(".tw") as HTMLElement);
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

async function shown() {
  open();
  await section();
  show();
  await waitFor(() => expect(folders().length).toBeGreaterThan(0));
}

describe("the cache page", () => {
  it("reads nothing until asked, then shows the tree with the root expanded to the top-level domains", async () => {
    open();
    await section();
    // The explanation sits behind the info button beside the title, not above the data.
    expect(screen.queryByTestId("dns-cache-audit-note")).toBeNull();
    const info = screen.getByTestId("page-info");
    expect(info.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(info);
    expect(info.getAttribute("aria-expanded")).toBe("true");
    expect((await screen.findByTestId("dns-cache-audit-note")).textContent).toContain("recorded in the audit log");
    fireEvent.keyDown(screen.getByTestId("page-info-popover"), { key: "Escape" });
    expect(screen.queryByTestId("dns-cache-audit-note")).toBeNull();
    expect(screen.getByTestId("dns-cache-show").textContent).toBe("Show the entries");
    expect(screen.queryByTestId("dns-cache-tree")).toBeNull();
    expect(reads()).toHaveLength(0);
    expect(requests).toHaveLength(0);
    show();
    await waitFor(() => expect(folders()).toEqual([".", "net", "org", "test"]));
    expect(screen.getByTestId("dns-cache-show").textContent).toBe("Read again");
    expect(folder(".").textContent).toBe("(root)");
    expect(folder(".").getAttribute("aria-expanded")).toBe("true");
    expect(folder(".").getAttribute("aria-level")).toBe("1");
    expect(folder("test").getAttribute("aria-expanded")).toBe("false");
    expect(folder("test").getAttribute("aria-level")).toBe("2");
    expect(folder("net").textContent).toBe("net");
    expect(selected()).toBe(".");
    expect(pane()).toEqual(["folder net", "folder org", "folder test"]);
    expect(requests.map((q) => q.get("limit"))).toEqual(["1000"]);
    expect(reads()).toHaveLength(1);
    expect(reads()[0]?.draft.details?.context).toMatchObject({ from_cursor: "first", to_cursor: "end", entries: "9" });
  });

  it("expands, collapses and selects folders without reading, and reads only on the button", async () => {
    await shown();
    toggleFolder("test");
    expect(folders()).toEqual([".", "net", "org", "test", "example.test"]);
    expect(folder("test").getAttribute("aria-expanded")).toBe("true");
    expect(selected()).toBe(".");
    selectFolder("example.test");
    expect(selected()).toBe("example.test");
    expect(screen.getByTestId("dns-cache-folder").textContent).toBe("example.test");
    selectFolder("net");
    expect(pane()).toEqual(["example.net HTTPS", "example.net SVCB", "example.net TXT"]);
    toggleFolder("org");
    toggleFolder("example.org");
    toggleFolder("test");
    expect(folders()).toEqual([".", "net", "org", "example.org", "test"]);
    selectFolder(".");
    fireEvent.dblClick(folderRow("test"));
    fireEvent.keyDown(folderRow("example.test"), { key: "Enter" });
    fireEvent.keyDown(tree(), { key: "ArrowUp" });
    fireEvent.keyDown(tree(), { key: "Home" });
    fireEvent.keyDown(tree(), { key: "End" });
    expect(requests).toHaveLength(1);
    expect(reads()).toHaveLength(1);
    show();
    await waitFor(() => expect(requests).toHaveLength(2));
    await waitFor(() => expect(reads()).toHaveLength(2));
    // A new read starts the tree afresh.
    await waitFor(() => expect(folders()).toEqual([".", "net", "org", "test"]));
    expect(selected()).toBe(".");
  });

  it("lists a folder's own records as the same as the parent folder, then the names under it with their signatures", async () => {
    await shown();
    toggleFolder("test");
    selectFolder("example.test");
    expect(pane()).toEqual([
      "(same) MX",
      "intranet.example.test A",
      "missing.example.test A",
      "www.example.test A",
      "www.example.test RRSIG CNAME",
      "www.example.test RRSIG A",
      "www.example.test AAAA",
    ]);
    expect(cells(row("example.test", "MX"))).toEqual(["(same as parent folder)", "MX", "56 min", "Default", "Unvalidated", "", "3", "10 mail.example.test"]);
    expect(row("example.test", "MX").querySelector(".dns-cache-same")?.classList.contains("muted")).toBe(true);
    expect(cells(row("www.example.test", "A"))).toEqual(["www", "A", "4 min", "Default", "Secure", "", "41", "CNAME cdn.example.test, 192.0.2.80"]);
    expect(cells(row("www.example.test", "RRSIG", "A"))).toEqual(["www", "RRSIG", "4 min", "Default", "", "", "", "A, signer example.test, expires 2026-11-12 02:08"]);
    expect(within(row("www.example.test", "RRSIG", "CNAME")).getByTestId("dns-cache-data").textContent).toBe(
      "CNAME, signer example.test, expires 2026-11-12 02:08",
    );
    expect(cells(row("www.example.test", "AAAA"))[7]).toBe("2001:db8::80");
    expect(cells(row("intranet.example.test", "A"))[3]).toBe(CACHE_VIEW);
    expect(cells(row("missing.example.test", "A"))).toEqual(["missing", "A", "–", "Default", "Unvalidated", "Stale", "0", "NXDOMAIN"]);
    expect(screen.getAllByTestId("dns-cache-stale")).toHaveLength(1);
  });

  it("shows HTTPS and SVCB data as SvcParams in the data font, not as JSON", async () => {
    await shown();
    selectFolder("net");
    const https = within(row("example.net", "HTTPS")).getByTestId("dns-cache-data");
    expect(https.textContent).toBe("1 . alpn=h2,h3 ipv4hint=192.0.2.10 ipv6hint=2001:db8::10");
    expect(https.classList.contains("mono")).toBe(true);
    expect(within(row("example.net", "SVCB")).getByTestId("dns-cache-data").textContent).toBe("1 svc.example.net alpn=h2 port=8443");
  });

  it("keeps the state badges and the plain header when the states differ", async () => {
    await shown();
    selectFolder("net");
    // The HTTPS and SVCB rows are insecure, the TXT row is unvalidated.
    expect(screen.getByTestId("dns-cache-state-head").textContent).toBe("State");
    expect(screen.getByTestId("dns-cache-state-head").dataset.said).toBeUndefined();
    const states = ["HTTPS", "SVCB", "TXT"].map((type) => within(row("example.net", type)).getByTestId("dns-cache-state").textContent);
    expect(states).toEqual(["Insecure", "Insecure", "Unvalidated"]);
  });

  it("says the state once in the header and draws no badge when every row has it, keeping Stale on its row", async () => {
    for (const e of dnsCacheState().entries) if (e.name === "example.net") e.state = "insecure";
    const txt = dnsCacheState().entries.find((e) => e.name === "example.net" && e.type === "TXT")!;
    txt.stale = true;
    await shown();
    selectFolder("net");
    const head = screen.getByTestId("dns-cache-state-head");
    expect(head.textContent).toBe("State · all insecure");
    expect(head.dataset.said).toBe("insecure");
    for (const type of ["HTTPS", "SVCB", "TXT"]) {
      const cell = within(row("example.net", type)).getByTestId("dns-cache-state");
      expect(cell.textContent).toBe("");
      expect(cell.querySelector(".tag")).toBeNull();
    }
    expect(screen.getAllByTestId("dns-cache-stale")).toHaveLength(1);
    expect(within(row("example.net", "TXT")).getByTestId("dns-cache-stale").textContent).toBe("Stale");
    // Another folder is judged on its own rows: the header says "State" again where they differ.
    selectFolder(".");
    expect(screen.getByTestId("dns-cache-state-head").textContent).toBe("State");
  });

  it("keeps the signature expiry on the cell when the state is said once", async () => {
    const [secure] = dnsCacheState().entries.filter((e) => e.name === "www.example.test" && e.type === "A");
    for (const e of dnsCacheState().entries) if (e.name.endsWith("example.test")) e.state = "secure";
    if (secure) secure.signature_expiry = "2026-11-01T00:00:00Z";
    await shown();
    toggleFolder("test");
    selectFolder("example.test");
    expect(screen.getByTestId("dns-cache-state-head").textContent).toBe("State · all secure");
    const cell = within(row("www.example.test", "A")).getByTestId("dns-cache-state");
    expect(cell.querySelector(".tag")).toBeNull();
    expect(cell.getAttribute("title")).toContain("Signatures valid until");
  });

  it("says the state once in Swedish", async () => {
    for (const e of dnsCacheState().entries) if (e.name === "example.net") e.state = "insecure";
    await setLocale("sv");
    await shown();
    selectFolder("net");
    expect(screen.getByTestId("dns-cache-state-head").textContent).toBe("Tillstånd · alla osäkra");
  });

  it("shows the validation state of each entry and the extended error code of a bogus one", async () => {
    await shown();
    toggleFolder("org");
    selectFolder("example.org");
    const [bogus] = rows();
    expect(cells(bogus as HTMLElement).slice(0, 2)).toEqual(["ns1", "AAAA"]);
    expect(within(bogus as HTMLElement).getByTestId("dns-cache-state").dataset.state).toBe("bogus");
    expect(within(bogus as HTMLElement).getByTestId("dns-cache-ede").textContent).toBe("EDE 6");
    expect(within(bogus as HTMLElement).getByTestId("dns-cache-data").textContent).toBe("NODATA");
    toggleFolder("test");
    selectFolder("example.test");
    const secure = rows().find((r) => r.dataset.key === "www.example.test" && r.dataset.type === "A") as HTMLElement;
    expect(within(secure).getByTestId("dns-cache-state").querySelector(".tag")?.getAttribute("title")).toContain("Signatures valid until");
    expect(within(secure).queryByTestId("dns-cache-ede")).toBeNull();
    selectFolder("net");
    expect(cells(row("example.net", "TXT"))[2]).toBe("3 h");
  });

  it("moves through the tree with the keyboard, opening, closing and selecting folders", async () => {
    await shown();
    const list = tree();
    fireEvent.keyDown(list, { key: "ArrowDown" });
    expect(selected()).toBe("net");
    expect(list.getAttribute("aria-activedescendant")).toBe(folder("net").id);
    fireEvent.keyDown(list, { key: "End" });
    expect(selected()).toBe("test");
    fireEvent.keyDown(list, { key: "ArrowRight" });
    expect(folder("test").getAttribute("aria-expanded")).toBe("true");
    expect(selected()).toBe("test");
    fireEvent.keyDown(list, { key: "ArrowRight" });
    expect(selected()).toBe("example.test");
    fireEvent.keyDown(list, { key: "ArrowLeft" });
    expect(selected()).toBe("test");
    fireEvent.keyDown(list, { key: "ArrowLeft" });
    expect(folder("test").getAttribute("aria-expanded")).toBe("false");
    expect(folders()).toEqual([".", "net", "org", "test"]);
    fireEvent.keyDown(list, { key: "Home" });
    expect(selected()).toBe(".");
    fireEvent.keyDown(list, { key: "ArrowLeft" });
    expect(folders()).toEqual(["."]);
    expect(requests).toHaveLength(1);
  });

  it("gives a closed folder the selection inside it", async () => {
    await shown();
    toggleFolder("test");
    selectFolder("example.test");
    toggleFolder("test");
    expect(selected()).toBe("test");
  });

  it("opens a folder from its row in the right pane on a double click or Enter", async () => {
    await shown();
    fireEvent.dblClick(folderRow("test"));
    expect(selected()).toBe("test");
    expect(folder("test").getAttribute("aria-expanded")).toBe("false");
    expect(pane()).toEqual(["folder example.test"]);
    fireEvent.keyDown(folderRow("example.test"), { key: "Enter" });
    expect(selected()).toBe("example.test");
    expect(folders()).toEqual([".", "net", "org", "test", "example.test"]);
    expect(document.activeElement).toBe(tree());
    expect(requests).toHaveLength(1);
  });

  it("narrows the read to a suffix, checks it first, and opens the path to its folder", async () => {
    open();
    await section();
    suffix("not a name");
    show();
    expect((await screen.findByTestId("field-error")).dataset.field).toBe("suffix");
    expect(reads()).toHaveLength(0);
    suffix("Example.Test.");
    show();
    await waitFor(() => expect(folders()).toEqual([".", "test", "example.test"]));
    expect(folder(".").getAttribute("aria-expanded")).toBe("true");
    expect(folder("test").getAttribute("aria-expanded")).toBe("true");
    expect(selected()).toBe("example.test");
    expect(rows()).toHaveLength(7);
    expect(screen.queryByTestId("field-error")).toBeNull();
    expect(requests.at(-1)?.get("suffix")).toBe("example.test");
    expect(reads().at(-1)?.draft.details?.context).toMatchObject({ "filter.suffix": "example.test" });
    // A suffix that is a name without names under it is a folder of its own.
    suffix("www.example.test");
    show();
    await waitFor(() => expect(folders()).toEqual([".", "test", "example.test", "www.example.test"]));
    expect(selected()).toBe("www.example.test");
    expect(pane()).toEqual(["(same) A", "(same) RRSIG CNAME", "(same) RRSIG A", "(same) AAAA"]);
    suffix("nothing.example.test");
    show();
    expect((await screen.findByTestId("dns-cache-empty")).textContent).toContain("No entries for nothing.example.test");
    expect(screen.queryByTestId("dns-cache-tree")).toBeNull();
  });

  it("follows the cursor up to ten pages and says when the cap cut the read short", async () => {
    const state = dnsCacheState();
    const template = state.entries.find((e) => e.name === "www.example.test" && e.type === "AAAA")!;
    state.entries = Array.from({ length: 10_050 }, (_, n) => ({ ...template, name: `h${String(n).padStart(5, "0")}.example.test` }));
    open();
    await section();
    suffix("example.test");
    show();
    expect(await screen.findByTestId("dns-cache-capped", {}, { timeout: 10_000 })).toBeTruthy();
    expect(screen.getByTestId("dns-cache-capped").textContent).toContain("first 10,000 entries");
    expect(requests.map((q) => q.get("cursor") ?? "first")).toEqual(["first", ...Array.from({ length: 9 }, (_, n) => `p${(n + 1) * 1000}`)]);
    expect(reads()).toHaveLength(10);
    // The pane shows a window of the 10,000 rows.
    expect(rows()).toHaveLength(200);
    expect(screen.getByText("200 of 10,000 rows shown")).toBeTruthy();
    fireEvent.click(screen.getByTestId("dns-cache-pane-more"));
    expect(rows()).toHaveLength(400);
    expect(requests).toHaveLength(10);
  });

  it("reads everything without a notice below the cap", async () => {
    const state = dnsCacheState();
    const template = state.entries[0]!;
    state.entries = Array.from({ length: 1_500 }, (_, n) => ({ ...template, name: `h${String(n).padStart(4, "0")}.example.test` }));
    await shown();
    expect(requests).toHaveLength(2);
    expect(screen.queryByTestId("dns-cache-capped")).toBeNull();
  });

  it("shows a window of the folders under a folder, with a show more for the rest", async () => {
    const state = dnsCacheState();
    const template = state.entries[0]!;
    state.entries = Array.from({ length: 250 }, (_, n) => ({ ...template, name: `www.d${String(n).padStart(3, "0")}.example.test` }));
    open();
    await section();
    suffix("example.test");
    show();
    await waitFor(() => expect(folders()).toHaveLength(203));
    const more = screen.getByTestId("dns-cache-tree-more");
    expect(more.textContent).toBe("Show 50 more");
    expect(more.getAttribute("aria-level")).toBe("4");
    fireEvent.click(more.querySelector(".tnode") as HTMLElement);
    expect(folders()).toHaveLength(253);
    expect(screen.queryByTestId("dns-cache-tree-more")).toBeNull();
    expect(requests).toHaveLength(1);
  });

  it("flushes the suffix read after a confirmation and reads again", async () => {
    open();
    await section();
    expect(screen.queryByTestId("dns-cache-flush")).toBeNull();
    suffix("www.example.test");
    show();
    await waitFor(() => expect(rows().length).toBe(4));
    const flush = screen.getByTestId("dns-cache-flush");
    expect(flush.textContent).toBe("Flush www.example.test");
    fireEvent.click(flush);
    const dialog = await screen.findByTestId("dns-cache-flush-dialog");
    expect(dialog.textContent).toContain("Flush www.example.test from the cache?");
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dns-cache-flush-dialog")).toBeNull());
    expect(dnsCacheState().entries).toHaveLength(9);
    fireEvent.click(screen.getByTestId("dns-cache-flush"));
    fireEvent.click(within(await screen.findByTestId("dns-cache-flush-dialog")).getByTestId("confirm-ok"));
    expect(await screen.findByTestId("dns-cache-empty")).toBeTruthy();
    expect(dnsCacheState().entries).toHaveLength(7);
    expect(requests.map((q) => q.get("suffix"))).toEqual(["www.example.test", "www.example.test"]);
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
    expect(screen.queryByTestId("dns-cache-tree")).toBeNull();
  });

  it("is the cache tab, the last of the DNS tabs, and offers the node the log shows", async () => {
    open();
    await section();
    const tabs = screen.getAllByTestId("dns-nav-link");
    expect(tabs.at(-1)?.dataset.key).toBe("cache");
    expect(tabs.at(-1)?.getAttribute("aria-current")).toBe("page");
    expect((screen.getByTestId("field-node") as HTMLSelectElement).value).toBe("1");
  });

  it("says when the node does not run the DNS role", async () => {
    server.use(
      http.get("/api/v1/nodes/:id/dns", () =>
        HttpResponse.json(
          { type: "about:blank", status: 409, code: "dns.node.not_dns", title: "Not a DNS node", detail: "node 1 does not run the dns role", params: { node: "1" } },
          { status: 409, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    expect(await screen.findByTestId("dns-cache-not-dns")).toBeTruthy();
    expect(screen.queryByTestId("dns-cache-form")).toBeNull();
    expect(requests).toHaveLength(0);
  });

  it("says when the server has no DNS service", async () => {
    dnsNotBuilt();
    open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    expect(screen.queryByTestId("dns-cache-form")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await section();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Vad cachen innehåller");
    suffix("example.test");
    show();
    await waitFor(() => expect(rows().length).toBe(7));
    expect(folder(".").textContent).toBe("(rot)");
    expect(within(rows()[0] as HTMLElement).getAllByRole("cell")[0]?.textContent).toBe("(samma som överordnad mapp)");
    expect(screen.getByTestId("dns-cache-stale").textContent).toBe("Inaktuell");
    const signature = rows().find((r) => r.dataset.covered === "A") as HTMLElement;
    expect(within(signature).getByTestId("dns-cache-data").textContent).toBe("A, signerad av example.test, går ut 2026-11-12 02:08");
  });

  it("has no accessibility violations", async () => {
    const { container } = open();
    await section();
    suffix("example.test");
    show();
    await waitFor(() => expect(rows().length).toBe(7));
    expect(await axeViolations(container)).toEqual([]);
  });

  describe("the clamped data cell", () => {
    // jsdom has no layout: the heights the browser would report are stood in for.
    const heights = { scroll: 0, client: 0 };
    let scroll: PropertyDescriptor | undefined;
    let client: PropertyDescriptor | undefined;
    beforeEach(() => {
      scroll = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollHeight");
      client = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientHeight");
      Object.defineProperty(HTMLElement.prototype, "scrollHeight", { configurable: true, get: () => heights.scroll });
      Object.defineProperty(HTMLElement.prototype, "clientHeight", { configurable: true, get: () => heights.client });
    });
    afterEach(() => {
      if (scroll) Object.defineProperty(HTMLElement.prototype, "scrollHeight", scroll);
      if (client) Object.defineProperty(HTMLElement.prototype, "clientHeight", client);
    });

    it("clamps a value taller than three lines, with a button that opens and closes that cell", async () => {
      heights.scroll = 400;
      heights.client = 60;
      await shown();
      toggleFolder("org");
      selectFolder("example.org");
      const [first] = rows();
      const toggle = await within(first as HTMLElement).findByTestId("dns-cache-data-toggle");
      expect(toggle.textContent).toBe("Show all");
      expect(toggle.tagName).toBe("BUTTON");
      expect(toggle.getAttribute("aria-expanded")).toBe("false");
      const cell = within(first as HTMLElement).getByTestId("dns-cache-data");
      expect(cell.getAttribute("title")).toBe("NODATA");
      expect(cell.querySelector(".dns-cache-text")?.textContent).toBe("NODATA");
      fireEvent.click(toggle);
      expect(toggle.textContent).toBe("Show less");
      expect(toggle.getAttribute("aria-expanded")).toBe("true");
      expect(cell.querySelector(".dns-cache-text")?.classList.contains("open")).toBe(true);
      fireEvent.click(toggle);
      expect(toggle.textContent).toBe("Show all");
      expect(cell.querySelector(".dns-cache-text")?.classList.contains("open")).toBe(false);
    });

    it("shows no button on a value that fits", async () => {
      heights.scroll = 20;
      heights.client = 20;
      await shown();
      expect(screen.queryAllByTestId("dns-cache-data-toggle")).toHaveLength(0);
    });
  });
});
