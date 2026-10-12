import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { access, ACCESS_IDS, seedAccess } from "../../api/mock/access-store";
import { db } from "../../api/mock/db";
import { IPAM_IDS } from "../../api/mock/ipam/seed";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { setSessionForTest } from "../../auth/session";
import { signInAs } from "../testkit";
import AccessPage from "./AccessPage";
import { grantText, scopeText, validAccountName } from "./model";

// The dialogs render in a portal outside the view; axe looks at the whole document there.
const NO_SHELL = { disable: ["region"] } as const;

beforeEach(async () => {
  await signInAs();
  seedAccess();
});

afterEach(() => setSessionForTest(null));

async function openPage() {
  const view = renderRoute(AccessPage, { url: "/settings/access", path: "/settings/access" });
  await screen.findAllByTestId("access-grant");
  return view;
}

const grantRows = () => screen.getAllByTestId("access-grant");

describe("the roles", () => {
  it("lists the four roles with what they may and the sign-in each needs", async () => {
    await openPage();
    const rows = screen.getAllByTestId("access-role");
    expect(rows.map((r) => r.dataset.key)).toEqual(["admin", "operator", "viewer", "auditor"]);
    const auditor = rows[3]!;
    expect(auditor.textContent).toContain("Reads the audit log, the audit export status and the system status, nothing else.");
    expect(auditor.textContent).toContain("Globally only");
    expect(rows[1]!.textContent).toContain("Globally or through a grant");
    // The Standard profile asks administrators for MFA.
    await waitFor(() => expect(within(rows[0]!).getByTestId("access-role-mfa").dataset.mfa).toBe("totp_or_stronger"));
    expect(within(rows[2]!).getByTestId("access-role-mfa").dataset.mfa).toBe("optional");
    expect(rows[2]!.textContent).toContain("Follows the profile");
  });

  it("stores a policy for a role and follows the profile again", async () => {
    await openPage();
    const viewer = () => screen.getAllByTestId("access-role")[2]!;
    await waitFor(() => expect((within(viewer()).getByTestId("access-role-policy-edit") as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(within(viewer()).getByTestId("access-role-policy-edit"));
    let dialog = await screen.findByTestId("dialog-role-policy");
    fireEvent.click(within(dialog).getByTestId("field-mfa-passkey"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-role-policy")).toBeNull());
    expect(access.policies.get("viewer")).toBe("passkey");
    await waitFor(() => expect(within(viewer()).getByTestId("access-role-mfa").dataset.mfa).toBe("passkey"));
    expect(screen.getByText("Sign-in of the role Viewer saved")).toBeTruthy();

    fireEvent.click(within(viewer()).getByTestId("access-role-policy-edit"));
    dialog = await screen.findByTestId("dialog-role-policy");
    expect((within(dialog).getByTestId("field-mfa-passkey") as HTMLInputElement).checked).toBe(true);
    fireEvent.click(within(dialog).getByTestId("field-mfa-profile"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(access.policies.has("viewer")).toBe(false));
  });

  it("says when a policy is weaker than the profile", async () => {
    db.settings.mfa = "everyone";
    await openPage();
    const viewer = () => screen.getAllByTestId("access-role")[2]!;
    await waitFor(() => expect((within(viewer()).getByTestId("access-role-policy-edit") as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(within(viewer()).getByTestId("access-role-policy-edit"));
    const dialog = await screen.findByTestId("dialog-role-policy");
    expect(within(dialog).queryByTestId("role-policy-weaker")).toBeNull();
    fireEvent.click(within(dialog).getByTestId("field-mfa-optional"));
    expect(within(dialog).getByTestId("role-policy-weaker").textContent).toContain("the profile wins");
  });
});

describe("the grants", () => {
  it("lists every grant with holder, role and scope in words", async () => {
    await openPage();
    const rows = grantRows();
    expect(rows.map((r) => r.dataset.key)).toEqual([ACCESS_IDS.operatorGrant, ACCESS_IDS.viewerGrant, ACCESS_IDS.serviceAccountGrant]);
    await waitFor(() =>
      expect(within(rows[0]!).getByTestId("access-grant-scope").textContent).toBe("prefix 203.0.113.0/24 and everything inside it"),
    );
    expect(rows[0]!.textContent).toContain("Casey Example");
    expect(rows[0]!.dataset.role).toBe("operator");
    expect(rows[2]!.textContent).toContain("DNS sync (service account)");
  });

  it("adds a grant through the scope picker", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("access-grant-add"));
    const dialog = await screen.findByTestId("dialog-grant");
    // Nothing chosen: the dialog says what is missing and sends nothing.
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("Choose who receives the grant.")).toBeTruthy();
    expect(within(dialog).getByText("Choose the VRF, site or prefix the grant applies to.")).toBeTruthy();

    const subject = within(dialog).getByTestId("field-subject") as HTMLSelectElement;
    await waitFor(() => expect(subject.options.length).toBeGreaterThan(2));
    fireEvent.change(subject, { target: { value: db.users.find((u) => u.name === "sam")!.id } });
    fireEvent.click(within(dialog).getByTestId("field-role-viewer"));
    fireEvent.click(within(dialog).getByTestId("field-scope-kind-site"));
    const object = within(dialog).getByTestId("field-scope-object") as HTMLSelectElement;
    await waitFor(() => expect([...object.options].some((o) => o.value === IPAM_IDS.site.garage)).toBe(true));
    fireEvent.change(object, { target: { value: IPAM_IDS.site.garage } });
    fireEvent.click(within(dialog).getByTestId("field-scope-subtree"));
    fireEvent.click(within(dialog).getByTestId("field-delegable"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(screen.queryByTestId("dialog-grant")).toBeNull());
    const stored = access.grants.find((g) => g.subject === db.users.find((u) => u.name === "sam")!.id);
    expect(stored).toMatchObject({
      role: "viewer",
      scope: { kind: "site", value: { id: IPAM_IDS.site.garage, subtree: false } },
      delegable: true,
    });
    await waitFor(() => expect(grantRows()).toHaveLength(4));
    expect(screen.getByText("Grant for sam added")).toBeTruthy();
  });

  it("shows the server's refusal of a duplicate in the dialog", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("access-grant-add"));
    const dialog = await screen.findByTestId("dialog-grant");
    const subject = within(dialog).getByTestId("field-subject") as HTMLSelectElement;
    await waitFor(() => expect([...subject.options].some((o) => o.value === ACCESS_IDS.scopedOperator)).toBe(true));
    fireEvent.change(subject, { target: { value: ACCESS_IDS.scopedOperator } });
    const object = within(dialog).getByTestId("field-scope-object") as HTMLSelectElement;
    await waitFor(() => expect([...object.options].some((o) => o.value === IPAM_IDS.prefix.documentation)).toBe(true));
    fireEvent.change(object, { target: { value: IPAM_IDS.prefix.documentation } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByRole("alert")).toBeTruthy();
    expect(screen.getByTestId("dialog-grant")).toBeTruthy();
    expect(access.grants).toHaveLength(3);
  });

  it("revokes a grant after a confirmation", async () => {
    await openPage();
    fireEvent.click(within(grantRows()[1]!).getByTestId("access-grant-revoke"));
    const dialog = await screen.findByTestId("dialog-confirm");
    expect(dialog.textContent).toContain("casey loses: Viewer over prefix 198.51.100.0/24 and everything inside it.");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(grantRows()).toHaveLength(2));
    expect(access.grants.some((g) => g.id === ACCESS_IDS.viewerGrant)).toBe(false);
    expect(screen.getByText("Grant of casey revoked")).toBeTruthy();
  });
});

describe("the service accounts", () => {
  it("lists the accounts with their owner and shows the tokens of one", async () => {
    await openPage();
    const account = await screen.findByTestId("access-service-account");
    expect(account.dataset.key).toBe("dns-sync");
    await waitFor(() => expect(account.textContent).toContain("owner: alex"));
    expect(account.textContent).toContain("grants only");
    fireEvent.click(within(account).getByTestId("access-service-account-tokens"));
    const tokens = await within(account).findByTestId("access-sa-tokens");
    const row = await within(tokens).findByTestId("access-sa-token");
    expect(row.dataset.key).toBe("ipam-readonly");
    await waitFor(() => expect(row.textContent).toContain("Viewer over site Home and its child sites"));
  });

  it("creates a service account", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("access-service-account-add"));
    const dialog = await screen.findByTestId("dialog-service-account");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "has space" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("Enter 1 to 64 characters without spaces.")).toBeTruthy();
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "prometheus" } });
    fireEvent.input(within(dialog).getByTestId("field-display_name"), { target: { value: "Metrics scraper" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-service-account")).toBeNull());
    const created = db.users.find((u) => u.name === "prometheus");
    expect(created?.password).toBeNull();
    expect(created?.display_name).toBe("Metrics scraper");
    await waitFor(() => expect(screen.getAllByTestId("access-service-account").map((a) => a.dataset.key)).toContain("prometheus"));
  });

  it("creates a scoped token for an account, shows it once and revokes it", async () => {
    await openPage();
    const account = await screen.findByTestId("access-service-account");
    fireEvent.click(within(account).getByTestId("access-service-account-tokens"));
    fireEvent.click(await within(account).findByTestId("access-sa-token-create"));
    const dialog = await screen.findByTestId("dialog-token");
    // A service account's tokens are always scoped: there is no choice of kind.
    expect(within(dialog).queryByTestId("field-kind-personal")).toBeNull();
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "scraper" } });
    // The first grant has no scope yet; the dialog insists.
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByTestId("token-grants-error")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("token-grant-remove"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(within(dialog).getByTestId("token-grants-error").textContent).toContain("at least one grant or special scope");
    fireEvent.click(within(dialog).getByTestId("field-token-scope-metrics"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    const shown = await screen.findByTestId("dialog-token-created");
    expect(within(shown).getByTestId("token-secret").textContent).toMatch(/^tnk_/);
    expect((within(shown).getByTestId("token-done") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(shown).getByTestId("token-stored"));
    fireEvent.click(within(shown).getByTestId("token-done"));
    await waitFor(() => expect(screen.queryByTestId("dialog-token-created")).toBeNull());

    const token = db.tokens.find((t) => t.info.name === "scraper");
    expect(token?.info).toMatchObject({ scoped: true, scopes: ["metrics"] });
    const row = await within(account).findByText("Read the metrics");
    fireEvent.click(within(row.closest("tr")!).getByTestId("access-sa-token-revoke"));
    fireEvent.click(within(await screen.findByTestId("dialog-confirm")).getByTestId("confirm-ok"));
    await waitFor(() => expect(db.tokens.some((t) => t.info.name === "scraper")).toBe(false));
  });
});

describe("accessibility", () => {
  it("has no violations on the page and in the grant dialog", async () => {
    const view = await openPage();
    await screen.findByTestId("access-service-account");
    expect(await axeViolations(view.container)).toEqual([]);
    fireEvent.click(screen.getByTestId("access-grant-add"));
    await screen.findByTestId("dialog-grant");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });

  it("reaches the grant dialog by keyboard and closes it with Escape", async () => {
    await openPage();
    const add = screen.getByTestId("access-grant-add");
    add.focus();
    fireEvent.click(add);
    const dialog = await screen.findByTestId("dialog-grant");
    await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("dialog-grant")).toBeNull());
    expect(document.activeElement).toBe(add);
  });
});

describe("the words of a grant", () => {
  it("names scopes by their objects, and the whole installation for a token grant without one", () => {
    const names = { vrf: () => "default", site: () => "Garage", prefix: () => "203.0.113.0/25" };
    expect(scopeText({ kind: "vrf", value: "v" }, names)).toBe("VRF default");
    expect(scopeText({ kind: "site", value: { id: "s", subtree: false } }, names)).toBe("site Garage only");
    expect(scopeText({ kind: "prefix", value: { id: "p", subtree: false } }, names)).toBe("prefix 203.0.113.0/25 only");
    expect(scopeText({ kind: "prefix", value: { id: "p", subtree: false } })).toBe("prefix p only");
    expect(grantText({ role: "viewer", scope: null })).toBe("Viewer over the whole installation");
  });

  it("checks service account names as the server does", () => {
    expect(validAccountName("dns-sync")).toBe(true);
    expect(validAccountName("")).toBe(false);
    expect(validAccountName("a b")).toBe(false);
    expect(validAccountName("x".repeat(65))).toBe(false);
    expect(validAccountName("tab\there")).toBe(false);
  });
});
