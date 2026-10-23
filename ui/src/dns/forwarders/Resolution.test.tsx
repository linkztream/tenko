// The default resolution of the forwarders page (WP10.4): the block with the implicit default
// view and one row per view, the profile's value beside "default", the choice of a view's
// resolution and what it sends (a value, or `default_resolution` to follow the profile again),
// the note for a root rule, what a viewer sees, a failed save, Swedish; and the two pure helpers
// the rows are made of.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { server } from "../../api/mock/node";
import { dnsResolverState, dnsViewsState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { resetToasts, signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { recordWrites } from "../testkit";
import ForwardersPage from "./ForwardersPage";
import { choiceOf, effectiveResolution } from "./Resolution";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  resetToasts();
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(ForwardersPage, { url: "/dns/forwarders", path: "/dns/forwarders" });

const block = () => screen.getByTestId("fwd-resolution");
const viewRows = () => within(block()).queryAllByTestId("fwd-resolution-view");
const viewRow = (name: string): HTMLElement => {
  const found = viewRows().find((r) => r.dataset.key === name);
  if (!found) throw new Error(`no view row ${name}: ${viewRows().map((r) => r.dataset.key).join(", ")}`);
  return found;
};
const select = (name: string) => within(viewRow(name)).getByTestId("fwd-resolution-select") as HTMLSelectElement;

async function loaded() {
  await waitFor(() => expect(viewRows()).toHaveLength(2));
}

describe("choiceOf and effectiveResolution", () => {
  it("reads a view's own resolution, and the profile's when it has none", () => {
    expect(choiceOf({ resolution: "refuse" })).toBe("refuse");
    expect(choiceOf({ resolution: "forward" })).toBe("forward");
    expect(choiceOf({})).toBe("default");
    expect(choiceOf({ resolution: null })).toBe("default");
    expect(effectiveResolution({ resolution: "refuse", profile_resolution: "recurse" })).toBe("refuse");
    expect(effectiveResolution({ resolution: null, profile_resolution: "forward" })).toBe("forward");
    expect(effectiveResolution({ profile_resolution: "recurse" })).toBe("recurse");
  });
});

describe("the default resolution", () => {
  it("shows the implicit default view and each view with the profile's value beside the default", async () => {
    const view = open();
    await loaded();
    expect(within(block()).getByRole("heading", { level: 2 }).textContent).toBe("Default resolution");
    const implicit = within(block()).getByTestId("fwd-resolution-default");
    expect(implicit.dataset.effective).toBe("recurse");
    expect(implicit.textContent).toContain("The implicit default view");
    expect(implicit.textContent).toContain("Profile default (recurse)");
    expect(viewRows().map((r) => r.dataset.key)).toEqual(["office", "encrypted clients"]);
    for (const name of ["office", "encrypted clients"]) {
      expect(viewRow(name).dataset.choice).toBe("default");
      expect(viewRow(name).dataset.effective).toBe("recurse");
      expect(select(name).value).toBe("default");
    }
    expect([...select("office").options].map((o) => o.value)).toEqual(["default", "recurse", "forward", "refuse"]);
    expect([...select("office").options].map((o) => o.textContent)).toEqual(["Profile default (recurse)", "Recurse", "Forward to the default forwarder", "Refuse"]);
    expect(select("office").getAttribute("aria-label")).toBe("Resolution of the view office");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("follows the profile's value the views report", async () => {
    for (const v of dnsViewsState().views) v.profile_resolution = "refuse";
    open();
    await loaded();
    expect(within(block()).getByTestId("fwd-resolution-default").dataset.effective).toBe("refuse");
    expect(within(block()).getByTestId("fwd-resolution-default").textContent).toContain("Profile default (refuse)");
    expect(viewRow("office").dataset.effective).toBe("refuse");
    expect([...select("office").options][0]?.textContent).toBe("Profile default (refuse)");
  });

  it("shows a view's own resolution as chosen and as the one in force", async () => {
    const office = dnsViewsState().views.find((v) => v.name === "office");
    if (!office) throw new Error("no office view");
    office.resolution = "forward";
    open();
    await loaded();
    expect(viewRow("office").dataset.choice).toBe("forward");
    expect(viewRow("office").dataset.effective).toBe("forward");
    expect(select("office").value).toBe("forward");
    expect(viewRow("encrypted clients").dataset.choice).toBe("default");
  });

  it("sends the resolution chosen with the view's revision and shows it at once", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const revision = dnsViewsState().views.find((v) => v.name === "office")?.revision;
    fireEvent.change(select("office"), { target: { value: "refuse" } });
    expect((await screen.findByTestId("toast")).textContent).toContain("The resolution of the view office was saved");
    const patches = writes().filter((w) => w.method === "PATCH");
    expect(patches).toHaveLength(1);
    expect(patches[0]?.url).toContain("/api/v1/dns/views/");
    expect(patches[0]?.body).toEqual({ resolution: "refuse" });
    const calls = vi.mocked(globalThis.fetch).mock.calls.filter(([, init]) => String(init?.method ?? "GET") === "PATCH");
    expect((calls[0]?.[1]?.headers as Record<string, string> | undefined)?.["If-Match"]).toBe(`"${revision}"`);
    await waitFor(() => expect(viewRow("office").dataset.choice).toBe("refuse"));
    expect(viewRow("office").dataset.effective).toBe("refuse");
    expect(select("office").value).toBe("refuse");
    // The other view and the implicit default view are untouched.
    expect(viewRow("encrypted clients").dataset.choice).toBe("default");
    expect(within(block()).getByTestId("fwd-resolution-default").dataset.effective).toBe("recurse");
    expect(dnsViewsState().views.find((v) => v.name === "office")?.resolution).toBe("refuse");
  });

  it("asks the view to follow the profile again when default is chosen", async () => {
    const office = dnsViewsState().views.find((v) => v.name === "office");
    if (!office) throw new Error("no office view");
    office.resolution = "refuse";
    const writes = recordWrites();
    open();
    await loaded();
    expect(select("office").value).toBe("refuse");
    fireEvent.change(select("office"), { target: { value: "default" } });
    await waitFor(() => expect(viewRow("office").dataset.choice).toBe("default"));
    expect(writes().filter((w) => w.method === "PATCH").map((w) => w.body)).toEqual([{ default_resolution: true }]);
    expect(viewRow("office").dataset.effective).toBe("recurse");
    expect(dnsViewsState().views.find((v) => v.name === "office")?.resolution).toBeUndefined();
  });

  it("sends nothing when the choice does not change", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    fireEvent.change(select("office"), { target: { value: "default" } });
    await Promise.resolve();
    expect(writes()).toHaveLength(0);
    expect(screen.queryByTestId("toast")).toBeNull();
  });

  it("says why the resolution could not be saved and keeps the old choice", async () => {
    server.use(
      http.patch("/api/v1/dns/views/:id", () =>
        HttpResponse.json(
          { type: "about:blank", status: 409, code: "sys.stale_revision", title: "Stale revision", detail: "the view changed", params: {} },
          { status: 409, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await loaded();
    fireEvent.change(select("office"), { target: { value: "forward" } });
    expect((await screen.findByTestId("toast")).textContent).toContain("The resolution could not be saved");
    await waitFor(() => expect(select("office").disabled).toBe(false));
    expect(viewRow("office").dataset.choice).toBe("default");
  });

  it("notes a root rule only while one exists", async () => {
    const first = open();
    await loaded();
    expect(screen.queryByTestId("fwd-resolution-root")).toBeNull();
    first.unmount();
    dnsResolverState().forwarders.push({
      id: "0190d1c2-0000-7000-8000-00000000dc02",
      suffix: ".",
      mode: "forward",
      validate: true,
      transport: "plain",
      upstreams: [{ address: "192.0.2.53" }],
      tls_name: null,
      view: null,
      description: null,
      revision: 1,
    });
    open();
    expect((await screen.findByTestId("fwd-resolution-root")).textContent).toBe("A root rule covers every name of the views it applies in, so there the default resolution is not reached.");
  });

  it("shows a viewer the resolutions without a select", async () => {
    await signInWithRoles(["viewer"]);
    const office = dnsViewsState().views.find((v) => v.name === "office");
    if (!office) throw new Error("no office view");
    office.resolution = "refuse";
    open();
    await loaded();
    expect(within(block()).queryAllByTestId("fwd-resolution-select")).toHaveLength(0);
    expect(viewRow("office").textContent).toBe("officeRefuse");
    expect(viewRow("encrypted clients").textContent).toBe("encrypted clientsProfile default (recurse)");
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(within(block()).getByRole("heading", { level: 2 }).textContent).toBe("Standarduppslagning");
    expect(within(block()).getByTestId("fwd-resolution-default").textContent).toContain("Profilens standard (rekursera)");
    expect([...select("office").options].map((o) => o.textContent)).toEqual([
      "Profilens standard (rekursera)",
      "Rekursera",
      "Vidarebefordra till standardvidarebefordraren",
      "Neka",
    ]);
    fireEvent.change(select("office"), { target: { value: "refuse" } });
    expect((await screen.findByTestId("toast")).textContent).toContain("Uppslagningen i vyn office sparades");
  });
});
