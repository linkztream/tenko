// The block lists page: the seeded lists with their source, version and action, create a URL
// list, the local checks and the refusals of the server, "fetch now" with the job that follows,
// the upload of a file into an uploaded list, edit with the revision, delete, what a viewer
// sees, and the states of the service (not built, switched off).
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LIST_URLS, RESOLVER_IDS } from "../../api/mock/dns-resolver-model";
import { dnsResolverState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { dnsNotBuilt, dnsSwitchedOff, recordWrites, row, rowAction, rowActions, rows } from "../testkit";
import ListsPage from "./ListsPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(ListsPage, { url: "/dns/lists", path: "/dns/lists" });

/** The keys of the lists shown. */
const keys = () => rows("dns-lists").map((r) => r.dataset.key);

const version = (name: string) => within(row("dns-lists", name)).queryByTestId("list-version");

/** Opens the create dialog and waits for it. */
async function openCreate(): Promise<HTMLElement> {
  fireEvent.click(screen.getByTestId("dns-list-create"));
  return screen.findByTestId("dialog-list-form");
}

/** The `If-Match` header of the writes sent, in order. */
function ifMatchOfWrites(): (string | undefined)[] {
  return vi
    .mocked(globalThis.fetch)
    .mock.calls.filter(([, init]) => String(init?.method ?? "GET") !== "GET")
    .map(([, init]) => (init?.headers as Record<string, string> | undefined)?.["If-Match"]);
}

describe("the block lists", () => {
  it("lists the two lists of the seed with their source, version and action", async () => {
    const view = open();
    await waitFor(() => expect(keys()).toEqual(["Ads", "Local"]));
    const ads = row("dns-lists", "Ads");
    expect(within(ads).getByTestId("list-source").dataset.kind).toBe("url");
    expect(ads.textContent).toContain(LIST_URLS.ads);
    expect(ads.textContent).toContain("every 24 hours");
    expect(within(ads).getByTestId("list-version").dataset.count).toBe("4");
    expect(within(ads).getByTestId("list-version").dataset.key).toBe("3");
    expect(within(ads).getByTestId("list-action").dataset.kind).toBe("nxdomain");
    expect(within(ads).queryByTestId("list-disabled")).toBeNull();
    expect(ads.textContent).toContain('"a1b2c3"');
    const local = row("dns-lists", "Local");
    expect(within(local).getByTestId("list-source").dataset.kind).toBe("upload");
    expect(within(local).getByTestId("list-disabled").textContent).toBe("Off");
    expect(within(local).getByTestId("list-action").dataset.kind).toBe("redirect");
    expect(within(local).getByTestId("list-action").textContent).toContain("192.0.2.80");
    expect(version("Local")).toBeNull();
    expect(local.textContent).toContain("Not read yet");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("creates a URL list and sends the body of the form", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    const dialog = await openCreate();
    expect((within(dialog).getByTestId("field-interval") as HTMLInputElement).value).toBe("24");
    expect((within(dialog).getByTestId("field-source-url") as HTMLInputElement).checked).toBe(true);
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Trackers" } });
    fireEvent.input(within(dialog).getByTestId("field-url"), { target: { value: LIST_URLS.trackers } });
    fireEvent.input(within(dialog).getByTestId("field-interval"), { target: { value: "6" } });
    fireEvent.change(within(dialog).getByTestId("field-format"), { target: { value: "hosts" } });
    fireEvent.change(within(dialog).getByTestId("field-action"), { target: { value: "nodata" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(keys()).toEqual(["Ads", "Local", "Trackers"]));
    expect(screen.queryByTestId("dialog-list-form")).toBeNull();
    const posts = writes().filter((w) => w.method === "POST");
    expect(posts).toHaveLength(1);
    expect(posts[0]?.url).toContain("/api/v1/dns/lists");
    expect(posts[0]?.body).toEqual({
      name: "Trackers",
      source: { kind: "url", url: LIST_URLS.trackers },
      format: "hosts",
      action: { kind: "nodata" },
      enabled: true,
      interval_hours: 6,
      description: null,
    });
    const made = dnsResolverState().lists.find((l) => l.name === "Trackers");
    expect(made?.interval_hours).toBe(6);
    expect(within(row("dns-lists", "Trackers")).getByTestId("list-action").dataset.kind).toBe("nodata");
  });

  it("creates an uploaded list with a redirect and no interval", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Mine" } });
    fireEvent.click(within(dialog).getByTestId("field-source-upload"));
    expect(within(dialog).queryByTestId("field-url")).toBeNull();
    expect(within(dialog).queryByTestId("field-interval")).toBeNull();
    expect(within(dialog).getByTestId("field-file")).toBeTruthy();
    fireEvent.change(within(dialog).getByTestId("field-action"), { target: { value: "redirect" } });
    fireEvent.input(within(dialog).getByTestId("field-redirect"), { target: { value: "2001:DB8::80" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(keys()).toEqual(["Ads", "Local", "Mine"]));
    expect(writes().filter((w) => w.method === "POST")[0]?.body).toEqual({
      name: "Mine",
      source: { kind: "upload" },
      format: "domains",
      action: { kind: "redirect", address: "2001:db8::80" },
      enabled: true,
      interval_hours: null,
      description: null,
    });
    expect(screen.queryByTestId("list-job")).toBeNull();
  });

  it("sends the file chosen for a new uploaded list at once and follows the job", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Mine" } });
    fireEvent.click(within(dialog).getByTestId("field-source-upload"));
    const file = new File(["a.example.test\nb.example.test\n"], "mine.txt", { type: "text/plain" });
    fireEvent.change(within(dialog).getByTestId("field-file"), { target: { files: [file] } });
    expect(dialog.textContent).toContain("mine.txt is sent when you save.");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const job = await screen.findByTestId("list-job");
    await waitFor(() => expect(version("Mine")?.dataset.count).toBe("2"));
    const made = dnsResolverState().lists.find((l) => l.name === "Mine");
    expect(writes().map((w) => `${w.method} ${new URL(w.url, "http://x").pathname}`)).toEqual(["POST /api/v1/dns/lists", `PUT /api/v1/dns/lists/${made?.id}/file`]);
    expect(within(job).getByTestId("list-job-open").getAttribute("href")).toMatch(/^\/jobs\//);
  });

  it("checks the form before it sends and names each field", async () => {
    const writes = recordWrites();
    const view = open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Trackers" } });
    fireEvent.input(within(dialog).getByTestId("field-url"), { target: { value: "ftp://lists.example.test/x" } });
    fireEvent.input(within(dialog).getByTestId("field-interval"), { target: { value: "0" } });
    fireEvent.change(within(dialog).getByTestId("field-action"), { target: { value: "redirect" } });
    fireEvent.input(within(dialog).getByTestId("field-redirect"), { target: { value: "not-an-address" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["url", "interval", "redirect"]));
    expect(within(dialog).getAllByTestId("field-error")[1]?.textContent).toContain("1");
    expect(within(dialog).getAllByTestId("field-error")[1]?.textContent).toContain("168");
    expect(writes()).toHaveLength(0);
    expect(await axeViolations(view.container)).toEqual([]);
    // Mending the fields lets the list through.
    fireEvent.input(within(dialog).getByTestId("field-url"), { target: { value: LIST_URLS.trackers } });
    fireEvent.input(within(dialog).getByTestId("field-interval"), { target: { value: "168" } });
    fireEvent.input(within(dialog).getByTestId("field-redirect"), { target: { value: "192.0.2.80" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(keys()).toContain("Trackers"));
    expect(writes()).toHaveLength(1);
  });

  it("checks the name before it sends", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-url"), { target: { value: LIST_URLS.trackers } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["name"]));
    expect(writes()).toHaveLength(0);
  });

  it("shows the refusal of the server under the field it names", async () => {
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "ads" } });
    fireEvent.input(within(dialog).getByTestId("field-url"), { target: { value: LIST_URLS.trackers } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const error = await within(dialog).findByTestId("field-error");
    expect(error.dataset.field).toBe("name");
    expect(error.textContent).toBe("The block list breaks a rule.");
    expect(dnsResolverState().lists).toHaveLength(2);
    expect(screen.getByTestId("dialog-list-form")).toBeTruthy();
  });
});

describe("fetch now", () => {
  it("starts the job, follows it to its end and shows the new version", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    expect(version("Ads")?.dataset.key).toBe("3");
    await rowAction(row("dns-lists", "Ads"), "fetch");
    const job = await screen.findByTestId("list-job");
    expect(writes().map((w) => `${w.method} ${new URL(w.url, "http://x").pathname}`)).toEqual([`POST /api/v1/dns/lists/${RESOLVER_IDS.list.ads}/fetch`]);
    await waitFor(() => expect(job.dataset.state).toBe("succeeded"), { timeout: 5000 });
    expect(within(job).getByTestId("list-job-open").getAttribute("href")).toBe(`/jobs/${job.dataset.id}`);
    await waitFor(() => expect(version("Ads")?.dataset.key).toBe("4"));
    expect(version("Ads")?.dataset.count).toBe("5");
    expect(screen.getByText("Fetching Ads")).toBeTruthy();
  });

  it("shows the last error of a URL that cannot be fetched", async () => {
    dnsResolverState().lists[0]!.source = { kind: "url", url: "https://nowhere.example.test/x.txt" };
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    await rowAction(row("dns-lists", "Ads"), "fetch");
    await waitFor(() => expect(within(row("dns-lists", "Ads")).getByTestId("list-last-error").dataset.code).toBe("dns.list.fetch_failed"));
    expect(version("Ads")?.dataset.key).toBe("3");
  });

  it("offers fetch for a URL list and upload for an uploaded one", async () => {
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    expect(await rowActions(row("dns-lists", "Ads"))).toEqual(["fetch", "edit", "delete"]);
    expect(await rowActions(row("dns-lists", "Local"))).toEqual(["upload", "edit", "delete"]);
  });
});

describe("the upload of a file", () => {
  const FILE = "# mine\n0.0.0.0 a.example.test b.example.test\n127.0.0.1 localhost\n0.0.0.0 c.example.test\n";

  it("sends the chosen file as text and shows the compiled count", async () => {
    recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    await rowAction(row("dns-lists", "Local"), "upload");
    const dialog = await screen.findByTestId("dialog-list-upload");
    expect(await axeViolations(dialog)).toEqual([]);
    const file = new File([FILE], "mine.hosts", { type: "text/plain" });
    // The jsdom of this project reads a File as text.
    expect(await file.text()).toBe(FILE);
    fireEvent.change(within(dialog).getByTestId("field-file"), { target: { files: [file] } });
    expect(dialog.textContent).toContain("mine.hosts is sent when you save.");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const job = await screen.findByTestId("list-job");
    expect(screen.queryByTestId("dialog-list-upload")).toBeNull();
    const puts = vi.mocked(globalThis.fetch).mock.calls.filter(([, init]) => init?.method === "PUT");
    expect(puts).toHaveLength(1);
    const [url, init] = puts[0]!;
    expect(new URL(String(url), "http://x").pathname).toBe(`/api/v1/dns/lists/${RESOLVER_IDS.list.local}/file`);
    expect(await (init?.body as Blob).text()).toBe(FILE);
    expect((init?.body as Blob).type).toBe("text/plain");
    await waitFor(() => expect(version("Local")?.dataset.count).toBe("3"));
    expect(version("Local")?.dataset.key).toBe("1");
    await waitFor(() => expect(job.dataset.state).toBe("succeeded"), { timeout: 5000 });
    expect(within(job).getByTestId("list-job-open").getAttribute("href")).toBe(`/jobs/${job.dataset.id}`);
  });

  it("asks for a file before it sends", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    await rowAction(row("dns-lists", "Local"), "upload");
    const dialog = await screen.findByTestId("dialog-list-upload");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("field-error")).dataset.field).toBe("file");
    expect(writes()).toHaveLength(0);
    fireEvent.click(within(dialog).getByTestId("form-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-list-upload")).toBeNull());
  });
});

describe("edit and delete", () => {
  it("edits a list with its revision and keeps the kind of its source", async () => {
    recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    const revision = dnsResolverState().lists.find((l) => l.name === "Ads")!.revision;
    await rowAction(row("dns-lists", "Ads"), "edit");
    const dialog = await screen.findByTestId("dialog-list-form");
    expect((within(dialog).getByTestId("field-name") as HTMLInputElement).value).toBe("Ads");
    expect((within(dialog).getByTestId("field-url") as HTMLInputElement).value).toBe(LIST_URLS.ads);
    expect((within(dialog).getByTestId("field-interval") as HTMLInputElement).value).toBe("24");
    expect((within(dialog).getByTestId("field-source-upload") as HTMLInputElement).disabled).toBe(true);
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.input(within(dialog).getByTestId("field-interval"), { target: { value: "12" } });
    fireEvent.change(within(dialog).getByTestId("field-action"), { target: { value: "nodata" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(row("dns-lists", "Ads")).getByTestId("list-action").dataset.kind).toBe("nodata"));
    const patches = vi.mocked(globalThis.fetch).mock.calls.filter(([, init]) => init?.method === "PATCH");
    expect(patches).toHaveLength(1);
    expect(String(patches[0]![0])).toContain(`/api/v1/dns/lists/${RESOLVER_IDS.list.ads}`);
    expect(ifMatchOfWrites()).toEqual([`"${revision}"`]);
    expect(JSON.parse(patches[0]![1]!.body as string)).toMatchObject({ name: "Ads", interval_hours: 12, action: { kind: "nodata" }, source: { kind: "url", url: LIST_URLS.ads } });
    expect(dnsResolverState().lists.find((l) => l.name === "Ads")?.interval_hours).toBe(12);
    expect(row("dns-lists", "Ads").textContent).toContain("every 12 hours");
  });

  it("edits the uploaded list with a redirect and shows no URL fields", async () => {
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    await rowAction(row("dns-lists", "Local"), "edit");
    const dialog = await screen.findByTestId("dialog-list-form");
    expect((within(dialog).getByTestId("field-redirect") as HTMLInputElement).value).toBe("192.0.2.80");
    expect((within(dialog).getByTestId("field-source-url") as HTMLInputElement).disabled).toBe(true);
    expect(within(dialog).queryByTestId("field-url")).toBeNull();
    expect((within(dialog).getByTestId("field-enabled") as HTMLInputElement).checked).toBe(false);
    fireEvent.click(within(dialog).getByTestId("field-enabled"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(row("dns-lists", "Local")).queryByTestId("list-disabled")).toBeNull());
    expect(dnsResolverState().lists.find((l) => l.name === "Local")?.enabled).toBe(true);
  });

  it("shows the refusal of a stale revision in the dialog", async () => {
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    await rowAction(row("dns-lists", "Ads"), "edit");
    const dialog = await screen.findByTestId("dialog-list-form");
    // Another person saved the list meanwhile.
    dnsResolverState().lists.find((l) => l.name === "Ads")!.revision += 100;
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("error-notice")).dataset.code).toBe("sys.store.precondition_failed");
  });

  it("deletes a list after the confirmation, with its revision", async () => {
    recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    const revision = dnsResolverState().lists.find((l) => l.name === "Local")!.revision;
    await rowAction(row("dns-lists", "Local"), "delete");
    const dialog = await screen.findByTestId("dialog-list-delete");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(keys()).toEqual(["Ads"]));
    expect(dnsResolverState().lists.map((l) => l.name)).toEqual(["Ads"]);
    expect(ifMatchOfWrites()).toEqual([`"${revision}"`]);
  });

  it("keeps the list when the deletion is cancelled", async () => {
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    await rowAction(row("dns-lists", "Local"), "delete");
    const dialog = await screen.findByTestId("dialog-list-delete");
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-list-delete")).toBeNull());
    expect(dnsResolverState().lists).toHaveLength(2);
  });
});

describe("what a viewer sees", () => {
  it("lists the block lists without create or any action", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await waitFor(() => expect(keys()).toEqual(["Ads", "Local"]));
    expect(screen.queryByTestId("dns-list-create")).toBeNull();
    expect(await rowActions(row("dns-lists", "Ads"))).toEqual([]);
    expect(await rowActions(row("dns-lists", "Local"))).toEqual([]);
    fireEvent.dblClick(row("dns-lists", "Ads"));
    expect(screen.queryByTestId("dialog-list-form")).toBeNull();
    expect(within(row("dns-lists", "Ads")).getByTestId("list-version").dataset.count).toBe("4");
  });
});

describe("the states of the service", () => {
  it("says the service is not built yet and offers no change", async () => {
    dnsNotBuilt();
    const view = open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    expect(screen.queryByTestId("grid-dns-lists")).toBeNull();
    expect(screen.queryByTestId("dns-list-create")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("says the module is switched off", async () => {
    dnsSwitchedOff();
    open();
    expect(await screen.findByTestId("dns-off")).toBeTruthy();
    expect(screen.queryByTestId("grid-dns-lists")).toBeNull();
    expect(screen.queryByTestId("dns-list-create")).toBeNull();
  });
});

describe("accessibility and language", () => {
  it("has no violations with the create dialog open", async () => {
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    const dialog = await openCreate();
    expect(await axeViolations(dialog)).toEqual([]);
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await waitFor(() => expect(keys()).toHaveLength(2));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Blocklistor/);
  });
});
