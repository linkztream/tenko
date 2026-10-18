// The access lists and the TSIG keys: create and edit a list with its entries, the local check of
// an entry, a list in use refused; generate and import a key with the one-time secret, delete;
// the key pages only for holders of `dns.keys`.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { dnsState } from "../api/mock/routes-dns";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInWithRoles } from "../auth/scope-testkit";
import { setSessionForTest } from "../auth/session";
import { setLocale } from "../i18n";
import AclsPage from "./AclsPage";
import KeysPage from "./KeysPage";
import { dnsNotBuilt, recordWrites, row, rowAction, rows } from "./testkit";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

describe("the access lists", () => {
  const open = () => renderRoute(AclsPage, { url: "/dns/acls", path: "/dns/acls" });

  it("lists the access lists with their entries and the zones that use them", async () => {
    const view = open();
    await waitFor(() => expect(rows("dns-acls").map((r) => r.dataset.key)).toEqual(["internal", "transfer-peers"]));
    const peers = row("dns-acls", "transfer-peers");
    expect(within(peers).getAllByTestId("acl-entry").map((e) => e.textContent)).toEqual(["key xfr.example.test", "198.51.100.53/32"]);
    expect(peers.querySelector('[data-col="used_by"]')?.textContent).toBe("example.test");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("creates a list, checking each entry line first", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(rows("dns-acls")).toHaveLength(2));
    fireEvent.click(screen.getByTestId("dns-acl-create"));
    const dialog = await screen.findByTestId("dialog-acl-form");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "lab" } });
    fireEvent.input(within(dialog).getByTestId("field-entries"), { target: { value: "203.0.113.0/24\n!not-a-prefix\nany" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findByTestId("field-error")).textContent).toBe("Line 2 is not a prefix, a key or any.");
    expect(writes()).toHaveLength(0);
    fireEvent.input(within(dialog).getByTestId("field-entries"), { target: { value: "203.0.113.0/24\n!203.0.113.66\nkey xfr.example.test\n!any" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(rows("dns-acls")).toHaveLength(3));
    expect(dnsState().acls.find((a) => a.name === "lab")?.entries).toEqual([
      { kind: "prefix", prefix: "203.0.113.0/24" },
      { kind: "prefix", prefix: "203.0.113.66/32", deny: true },
      { kind: "key", name: "xfr.example.test" },
      { kind: "any", deny: true },
    ]);
  });

  it("edits a list with its revision", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(rows("dns-acls")).toHaveLength(2));
    await rowAction(row("dns-acls", "internal"), "edit");
    const dialog = await screen.findByTestId("dialog-acl-form");
    expect((within(dialog).getByTestId("field-entries") as HTMLTextAreaElement).value).toBe("192.0.2.0/24\n2001:db8::/32");
    fireEvent.input(within(dialog).getByTestId("field-entries"), { target: { value: "192.0.2.0/24" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(dnsState().acls.find((a) => a.name === "internal")?.entries).toHaveLength(1));
    expect(writes()[0]?.method).toBe("PATCH");
  });

  it("shows the refusal of a list in use", async () => {
    open();
    await waitFor(() => expect(rows("dns-acls")).toHaveLength(2));
    await rowAction(row("dns-acls", "transfer-peers"), "delete");
    const dialog = await screen.findByTestId("dialog-acl-delete");
    expect(within(dialog).getByText(/The list is used by example\.test/)).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    expect((await within(dialog).findByTestId("error-notice")).dataset.code).toBe("dns.acl.in_use");
    expect(dnsState().acls).toHaveLength(2);
  });

  it("deletes a list no zone uses", async () => {
    open();
    await waitFor(() => expect(rows("dns-acls")).toHaveLength(2));
    await rowAction(row("dns-acls", "internal"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-acl-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dns-acls").map((r) => r.dataset.key)).toEqual(["transfer-peers"]));
  });

  it("offers a viewer no change", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await waitFor(() => expect(rows("dns-acls")).toHaveLength(2));
    expect(screen.queryByTestId("dns-acl-create")).toBeNull();
    expect(screen.queryAllByTestId("dns-nav-link").map((l) => l.dataset.key)).toEqual(["zones", "acls", "log"]);
  });
});

describe("the TSIG keys", () => {
  const open = () => renderRoute(KeysPage, { url: "/dns/keys", path: "/dns/keys" });

  it("generates a key and shows its secret this once", async () => {
    open();
    await waitFor(() => expect(rows("dns-keys").map((r) => r.dataset.key)).toEqual(["xfr.example.test"]));
    fireEvent.click(screen.getByTestId("dns-key-create"));
    const form = await screen.findByTestId("dialog-key-form");
    fireEvent.input(within(form).getByTestId("field-name"), { target: { value: "ddns.example.test" } });
    fireEvent.change(within(form).getByTestId("field-algorithm"), { target: { value: "hmac-sha512" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    const shown = await screen.findByTestId("dialog-key-created");
    expect(within(shown).getByTestId("key-secret").textContent).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(await axeViolations(shown)).toEqual([]);
    const done = within(shown).getByTestId("key-done") as HTMLButtonElement;
    expect(done.disabled).toBe(true);
    // Esc does not close it before the secret is stored.
    fireEvent.keyDown(shown, { key: "Escape" });
    expect(screen.getByTestId("dialog-key-created")).toBeTruthy();
    fireEvent.click(within(shown).getByTestId("key-stored"));
    fireEvent.click(done);
    await waitFor(() => expect(screen.queryByTestId("dialog-key-created")).toBeNull());
    await waitFor(() => expect(rows("dns-keys").map((r) => r.dataset.key)).toEqual(["ddns.example.test", "xfr.example.test"]));
    expect(dnsState().keys.find((k) => k.name === "ddns.example.test")?.algorithm).toBe("hmac-sha512");
    // The list never carries a secret.
    expect(screen.queryByTestId("key-secret")).toBeNull();
  });

  it("imports a key with its secret and refuses a name that exists", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(rows("dns-keys")).toHaveLength(1));
    fireEvent.click(screen.getByTestId("dns-key-create"));
    const form = await screen.findByTestId("dialog-key-form");
    fireEvent.click(within(form).getByTestId("field-mode-import"));
    fireEvent.input(within(form).getByTestId("field-name"), { target: { value: "xfr.example.test" } });
    fireEvent.input(within(form).getByTestId("field-secret"), { target: { value: "not base64!" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    expect((await within(form).findByTestId("field-error")).dataset.field).toBe("secret");
    expect(writes()).toHaveLength(0);
    fireEvent.input(within(form).getByTestId("field-secret"), { target: { value: "c2VjcmV0LXZhbHVlLW9mLWEtdGVzdA==" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(within(form).getByTestId("field-error").textContent).toBe("A key of this name exists already."));
    fireEvent.input(within(form).getByTestId("field-name"), { target: { value: "peer.example.test" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    const shown = await screen.findByTestId("dialog-key-created");
    expect(within(shown).getByTestId("key-secret").textContent).toBe("c2VjcmV0LXZhbHVlLW9mLWEtdGVzdA==");
  });

  it("deletes a key after the confirmation", async () => {
    open();
    await waitFor(() => expect(rows("dns-keys")).toHaveLength(1));
    await rowAction(row("dns-keys", "xfr.example.test"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-key-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(rows("dns-keys")).toHaveLength(0));
    expect(await screen.findByTestId("dns-keys-empty")).toBeTruthy();
  });

  it("is in the navigation for administrators only", async () => {
    renderRoute(AclsPage, { url: "/dns/acls", path: "/dns/acls" });
    expect(screen.queryAllByTestId("dns-nav-link").map((l) => l.dataset.key)).toEqual(["zones", "acls", "keys", "log"]);
    await signInWithRoles(["operator"]);
    await waitFor(() => expect(screen.queryAllByTestId("dns-nav-link").map((l) => l.dataset.key)).toEqual(["zones", "acls", "log"]));
  });

  it("says the DNS service is not built yet when the server answers 501", async () => {
    dnsNotBuilt();
    open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    expect(screen.queryByTestId("dns-key-create")).toBeNull();
  });
});
