// The access parts of the user page and of the account's token page: the grants of one account,
// the tokens of a service account, and a scoped personal token.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";
import { access, ACCESS_IDS, seedAccess } from "../../api/mock/access-store";
import { db } from "../../api/mock/db";
import { IPAM_IDS } from "../../api/mock/ipam/seed";
import { renderRoute } from "../../app/testing/render";
import Account from "../../auth/account/Account";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import Settings from "../Settings";
import { SETTINGS_PATH, signInAs } from "../testkit";

afterEach(() => setSessionForTest(null));

function openUser(id: string) {
  return renderRoute(Settings, { url: `/settings/users/${id}`, path: SETTINGS_PATH });
}

describe("the user page", () => {
  it("shows the grants of a person and adds one with the holder fixed", async () => {
    await signInAs();
    seedAccess();
    openUser(ACCESS_IDS.scopedOperator);
    const section = await screen.findByTestId("access-grants");
    await waitFor(() => expect(within(section).getAllByTestId("access-grant")).toHaveLength(2));
    // One holder: no holder column.
    expect(within(section).queryByText("Holder")).toBeNull();
    fireEvent.click(within(section).getByTestId("access-grant-add"));
    const dialog = await screen.findByTestId("dialog-grant");
    const subject = within(dialog).getByTestId("field-subject") as HTMLSelectElement;
    expect(subject.disabled).toBe(true);
    await waitFor(() => expect(subject.value).toBe(ACCESS_IDS.scopedOperator));
    fireEvent.click(within(dialog).getByTestId("field-scope-kind-vrf"));
    const object = within(dialog).getByTestId("field-scope-object") as HTMLSelectElement;
    await waitFor(() => expect([...object.options].some((o) => o.value === IPAM_IDS.vrf.isolated)).toBe(true));
    fireEvent.change(object, { target: { value: IPAM_IDS.vrf.isolated } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(section).getAllByTestId("access-grant")).toHaveLength(3));
    expect(access.grants.at(-1)).toMatchObject({ subject: ACCESS_IDS.scopedOperator, role: "operator", scope: { kind: "vrf" } });
  });

  it("shows a service account's kind and tokens, without the actions of a person", async () => {
    await signInAs();
    seedAccess();
    openUser(ACCESS_IDS.serviceAccount);
    expect((await screen.findByTestId("user-kind")).textContent).toContain("Service account");
    const tokens = await screen.findByTestId("access-sa-tokens");
    expect((await within(tokens).findByTestId("access-sa-token")).dataset.key).toBe("ipam-readonly");
    expect(screen.queryByText("Sign out everywhere")).toBeNull();
  });

  it("shows no grants section for the break-glass account", async () => {
    await signInAs();
    openUser(db.users.find((u) => u.break_glass)!.id);
    await screen.findByRole("navigation", { name: "Breadcrumb" });
    await screen.findByText("breakglass", { selector: ".mono" });
    expect(screen.queryByTestId("access-grants")).toBeNull();
  });
});

describe("a scoped personal token", () => {
  it("is created with a grant over a prefix and listed with what it may do", async () => {
    await signInAlex();
    renderRoute(Account, { url: "/account/tokens", path: "/account/:section?" });
    fireEvent.click(await screen.findByRole("button", { name: "Create token" }));
    const dialog = await screen.findByTestId("dialog-token");
    fireEvent.input(within(dialog).getByLabelText("Name"), { target: { value: "lab sync" } });
    fireEvent.click(within(dialog).getByTestId("field-kind-scoped"));
    const grant = within(dialog).getByTestId("token-grant");
    fireEvent.click(within(grant).getByTestId("field-scope-kind-prefix"));
    const object = within(grant).getByTestId("field-scope-object") as HTMLSelectElement;
    await waitFor(() => expect([...object.options].some((o) => o.value === IPAM_IDS.prefix.lab)).toBe(true));
    fireEvent.change(object, { target: { value: IPAM_IDS.prefix.lab } });
    fireEvent.change(within(grant).getByTestId("field-token-role"), { target: { value: "operator" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await screen.findByRole("dialog", { name: "Your new token" });
    const token = db.tokens.find((t) => t.info.name === "lab sync");
    expect(token?.info).toMatchObject({
      scoped: true,
      grants: [{ role: "operator", scope: { kind: "prefix", value: { id: IPAM_IDS.prefix.lab, subtree: true } } }],
    });
    fireEvent.click(screen.getByLabelText("I have stored the token"));
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    const row = (await screen.findByText("lab sync")).closest("tr")!;
    await waitFor(() =>
      expect(within(row).getByTestId("token-reach").textContent).toBe("Operator over prefix 203.0.113.0/25 and everything inside it"),
    );
  });
});
