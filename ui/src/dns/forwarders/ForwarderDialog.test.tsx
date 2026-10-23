// The mode of a forwarding rule in its dialog (WP10.4): forward to upstreams (with the switch
// for DNSSEC validation) or recurse from the root servers, which has no upstream, transport or
// TLS name; what a create and an edit send for each, the refusals of the server for the mode,
// and Swedish. The dialogs are opened from the forwarders page, as a person opens them.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { server } from "../../api/mock/node";
import { dnsResolverState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { recordWrites, row, rowAction, rows } from "../testkit";
import ForwardersPage from "./ForwardersPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(ForwardersPage, { url: "/dns/forwarders", path: "/dns/forwarders" });

const keys = () => rows("dns-forwarders").map((r) => r.dataset.key);

async function openCreate(): Promise<HTMLElement> {
  fireEvent.click(await screen.findByTestId("dns-forwarder-create"));
  return screen.findByTestId("dialog-forwarder-form");
}

async function openEdit(key: string): Promise<HTMLElement> {
  await rowAction(row("dns-forwarders", key), "edit");
  return screen.findByTestId("dialog-forwarder-form");
}

function fieldError(dialog: HTMLElement, field: string): string | undefined {
  return dialog.querySelector(`[data-testid="field-error"][data-field="${field}"]`)?.textContent ?? undefined;
}

const radio = (dialog: HTMLElement, testid: string) => within(dialog).getByTestId(testid) as HTMLInputElement;

describe("the mode of a rule in the dialog", () => {
  it("starts a new rule as a forwarding rule with its upstreams, transport and validation", async () => {
    open();
    const dialog = await openCreate();
    expect(radio(dialog, "field-mode-forward").checked).toBe(true);
    expect(radio(dialog, "field-mode-recurse").checked).toBe(false);
    expect(radio(dialog, "field-mode-recurse").disabled).toBe(false);
    expect(within(dialog).getByTestId("field-upstreams")).toBeTruthy();
    expect(within(dialog).getByTestId("field-transport-plain")).toBeTruthy();
    expect(radio(dialog, "field-validate").checked).toBe(true);
    expect(within(dialog).queryByTestId("fwd-recurse-note")).toBeNull();
    expect(await axeViolations(dialog)).toEqual([]);
  });

  it("hides the upstreams, the transport and the validation for a recurse rule and says what it does", async () => {
    open();
    const dialog = await openCreate();
    fireEvent.click(within(dialog).getByTestId("field-mode-recurse"));
    expect(radio(dialog, "field-mode-recurse").checked).toBe(true);
    expect(within(dialog).queryByTestId("field-upstreams")).toBeNull();
    expect(within(dialog).queryByTestId("field-transport-plain")).toBeNull();
    expect(within(dialog).queryByTestId("field-validate")).toBeNull();
    expect(within(dialog).queryByTestId("field-tls_name")).toBeNull();
    expect(within(dialog).getByTestId("fwd-recurse-note").textContent).toContain("a recurse rule names no upstream and always validates");
    expect(await axeViolations(dialog)).toEqual([]);
    // Back to forwarding: the fields are there again.
    fireEvent.click(within(dialog).getByTestId("field-mode-forward"));
    expect(within(dialog).getByTestId("field-upstreams")).toBeTruthy();
    expect(within(dialog).queryByTestId("fwd-recurse-note")).toBeNull();
  });

  it("creates a recurse rule from the suffix and the description alone", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-suffix"), { target: { value: "Lab.Example.Test" } });
    fireEvent.click(within(dialog).getByTestId("field-mode-recurse"));
    fireEvent.input(within(dialog).getByTestId("field-description"), { target: { value: "Own resolution" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-forwarder-form")).toBeNull());
    const posts = writes().filter((w) => w.method === "POST");
    expect(posts).toHaveLength(1);
    expect(posts[0]?.body).toEqual({ suffix: "lab.example.test", mode: "recurse", description: "Own resolution" });
    await waitFor(() => expect(keys()).toEqual(["corp.example.test", "lab.example.test"]));
    const lab = row("dns-forwarders", "lab.example.test");
    expect(within(lab).getByTestId("fwd-transport").dataset.kind).toBe("recurse");
    expect(within(lab).getByTestId("fwd-recurse")).toBeTruthy();
    expect(dnsResolverState().forwarders.find((r) => r.suffix === "lab.example.test")).toMatchObject({ mode: "recurse", upstreams: [] });
    expect((await screen.findByTestId("toast")).textContent).toContain("lab.example.test");
  });

  it("sends no description of a recurse rule that has none", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(1));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-suffix"), { target: { value: "lab.example.test" } });
    fireEvent.click(within(dialog).getByTestId("field-mode-recurse"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-forwarder-form")).toBeNull());
    expect(writes().find((w) => w.method === "POST")?.body).toEqual({ suffix: "lab.example.test", mode: "recurse", description: null });
  });

  it("checks the suffix of a recurse rule before it sends anything", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(1));
    const dialog = await openCreate();
    fireEvent.click(within(dialog).getByTestId("field-mode-recurse"));
    fireEvent.input(within(dialog).getByTestId("field-suffix"), { target: { value: "*.example.test" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "suffix")).toBe("Not a DNS name."));
    // A recurse rule has no upstreams to complain about.
    expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["suffix"]);
    expect(writes()).toHaveLength(0);
  });

  it("sends validate false when the box is cleared, with the warning in place of the help", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(1));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-suffix"), { target: { value: "stripped.example.test" } });
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "192.0.2.53" } });
    expect(dialog.textContent).toContain("On by default.");
    fireEvent.click(within(dialog).getByTestId("field-validate"));
    expect(radio(dialog, "field-validate").checked).toBe(false);
    expect(dialog.textContent).toContain("The upstreams' answers are relayed unvalidated.");
    expect(dialog.textContent).not.toContain("On by default.");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-forwarder-form")).toBeNull());
    expect(writes().find((w) => w.method === "POST")?.body).toMatchObject({ suffix: "stripped.example.test", mode: "forward", validate: false });
    await waitFor(() => expect(within(row("dns-forwarders", "stripped.example.test")).getByTestId("fwd-unvalidated")).toBeTruthy());
  });

  it("opens an edit of a forwarding rule with the mode and the validation of the rule", async () => {
    const corp = dnsResolverState().forwarders[0];
    if (!corp) throw new Error("no seeded rule");
    corp.validate = false;
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    const dialog = await openEdit("corp.example.test");
    expect(radio(dialog, "field-mode-forward").checked).toBe(true);
    expect(radio(dialog, "field-validate").checked).toBe(false);
  });

  it("edits a forwarding rule into a recurse rule and clears what only a forwarding rule has", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    const dialog = await openEdit("corp.example.test");
    fireEvent.click(within(dialog).getByTestId("field-mode-recurse"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-forwarder-form")).toBeNull());
    const patches = writes().filter((w) => w.method === "PATCH");
    expect(patches).toHaveLength(1);
    expect(patches[0]?.body).toMatchObject({
      suffix: "corp.example.test",
      mode: "recurse",
      upstreams: [],
      transport: "plain",
      tls_name: "",
      validate: true,
    });
    await waitFor(() => expect(within(row("dns-forwarders", "corp.example.test")).getByTestId("fwd-transport").dataset.kind).toBe("recurse"));
    expect(within(row("dns-forwarders", "corp.example.test")).queryAllByTestId("fwd-upstream")).toHaveLength(0);
    expect(dnsResolverState().forwarders[0]).toMatchObject({ mode: "recurse", upstreams: [] });
  });

  it("edits a recurse rule back into a forwarding rule with upstreams", async () => {
    dnsResolverState().forwarders.push({
      id: "0190d1c2-0000-7000-8000-00000000dc10",
      suffix: "lab.example.test",
      mode: "recurse",
      validate: true,
      transport: "plain",
      upstreams: [],
      tls_name: null,
      view: null,
      description: null,
      revision: 1,
    });
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test", "lab.example.test"]));
    const dialog = await openEdit("lab.example.test");
    expect(radio(dialog, "field-mode-recurse").checked).toBe(true);
    expect(within(dialog).queryByTestId("field-upstreams")).toBeNull();
    fireEvent.click(within(dialog).getByTestId("field-mode-forward"));
    // A forwarding rule needs an upstream: the form checks that before it sends.
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "upstreams")).toBe("Give at least one upstream."));
    expect(writes()).toHaveLength(0);
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "192.0.2.53" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-forwarder-form")).toBeNull());
    expect(writes().find((w) => w.method === "PATCH")?.body).toMatchObject({ mode: "forward", upstreams: [{ address: "192.0.2.53" }], validate: true });
    await waitFor(() => expect(within(row("dns-forwarders", "lab.example.test")).getByTestId("fwd-transport").dataset.kind).toBe("plain"));
  });

  it("shows a refusal of the server for the mode under the mode", async () => {
    server.use(
      http.post("/api/v1/dns/forwarders", () =>
        HttpResponse.json(
          { type: "about:blank", status: 400, code: "dns.forwarder.invalid", title: "Invalid forwarder", detail: "validate: a recurse rule always validates", params: { field: "validate", reason: "a recurse rule always validates" } },
          { status: 400, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await waitFor(() => expect(keys()).toHaveLength(1));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-suffix"), { target: { value: "lab.example.test" } });
    fireEvent.click(within(dialog).getByTestId("field-mode-recurse"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "mode")).toBeTruthy());
    expect(within(dialog).queryByTestId("error-notice")).toBeNull();
    expect(screen.getByTestId("dialog-forwarder-form")).toBeTruthy();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    const dialog = await openCreate();
    expect(within(dialog).getByText("Läge")).toBeTruthy();
    expect(within(dialog).getByText("Vidarebefordra till uppströms resolvrar")).toBeTruthy();
    expect(within(dialog).getByText("Slå upp från rotservrarna (rekursera)")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("field-mode-recurse"));
    expect(within(dialog).getByTestId("fwd-recurse-note").textContent).toContain("en rekursionsregel anger ingen uppströmsserver");
  });
});
