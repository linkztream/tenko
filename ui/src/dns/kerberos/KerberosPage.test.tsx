// The Kerberos page (identity plan section 3.18, DNS-28, E45) against the mock API: the set-up
// offers the adopt and the keytab import; the adopt checks each step, shows the values an
// administrator types into the PowerShell block (values, never a script), sends the one-time
// password once and forgets it whatever the answer; the import reads the keytab file and sends
// it in base64url; the status shows the principal, who owns the password, the key versions and
// the SPNs, each finding with its fix, and the actions; the delete asks first; a session
// without `dns.keys` reads nothing; no accessibility violations; Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setMockKerberos } from "../../api/mock/routes-dns-kerberos";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import KerberosPage from "./KerberosPage";
import { KERBEROS_PATH } from "./paths";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(KerberosPage, { url: KERBEROS_PATH, path: KERBEROS_PATH });

const input = (testid: string, value: string) => fireEvent.input(screen.getByTestId(testid), { target: { value } });

async function adoptUntilPassword(): Promise<void> {
  fireEvent.click(await screen.findByTestId("kerberos-choose-adopt"));
  input("field-realm", "corp.example.test");
  input("field-kdcs", "dc1.corp.example.test\n192.0.2.5:88");
  fireEvent.click(screen.getByTestId("kerberos-next"));
  await screen.findByTestId("field-name");
  input("field-name", "tenko-dns");
  input("field-spns", "DNS/tenko1.corp.example.test\nHTTP/tenko1.corp.example.test");
  fireEvent.click(screen.getByTestId("kerberos-next"));
  await screen.findByTestId("field-password");
}

const account = {
  realm: "CORP.EXAMPLE.TEST",
  name: "TENKO-DNS$",
  principal: "TENKO-DNS$@CORP.EXAMPLE.TEST",
  spns: ["DNS/tenko1.corp.example.test"],
  kdcs: [],
  owned: true,
  rotation_days: 30,
  versions: [
    {
      kvno: 4,
      etypes: ["aes128-cts-hmac-sha1", "aes256-cts-hmac-sha1"] as const,
      state: "current" as const,
      created: "2026-11-01T10:00:00Z",
    },
    {
      kvno: 3,
      etypes: ["aes256-cts-hmac-sha1"] as const,
      state: "previous" as const,
      created: "2026-10-02T10:00:00Z",
    },
  ].map((v) => ({ ...v, etypes: [...v.etypes] })),
  last_rotation: "2026-11-01T10:00:00Z",
  next_rotation: "2026-12-01T10:00:00Z",
  last_check: "2026-11-06T10:00:00Z",
};

describe("the Kerberos set-up", () => {
  it("dns_28 adopts a pre-staged account step by step and shows its status", async () => {
    const view = open();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toMatch(/^Kerberos/);
    expect(await screen.findByTestId("kerberos-setup")).toBeTruthy();
    expect(await axeViolations(view.container)).toEqual([]);
    fireEvent.click(screen.getByTestId("kerberos-choose-adopt"));
    // Step 1 refuses a realm that is not one.
    input("field-realm", "corp example");
    fireEvent.click(screen.getByTestId("kerberos-next"));
    expect(screen.getByTestId("field-error").dataset.field).toBe("realm");
    input("field-realm", "corp.example.test");
    fireEvent.click(screen.getByTestId("kerberos-next"));
    // Step 2: the values for the administrator, as text, once name and SPNs are valid.
    await screen.findByTestId("field-name");
    expect(screen.queryByTestId("kerberos-block-values")).toBeNull();
    input("field-name", "tenko-dns");
    input("field-spns", "DNS/tenko1.corp.example.test\nDNS/tenko1.corp.example.test\nHTTP/tenko1.corp.example.test");
    const block = await screen.findByTestId("kerberos-block-values");
    expect(within(block).getByTestId("block-name").textContent).toBe("TENKO-DNS");
    expect(within(block).getByTestId("block-spn-0").textContent).toBe("DNS/tenko1.corp.example.test");
    expect(within(block).getByTestId("block-spn-1").textContent).toBe("HTTP/tenko1.corp.example.test");
    expect(within(block).queryByTestId("block-spn-2")).toBeNull();
    expect(within(block).getByTestId("block-realm").textContent).toBe("CORP.EXAMPLE.TEST");
    expect(block.textContent).toContain("docs/active-directory.md, section 4.1");
    expect(block.querySelector("pre")).toBeNull();
    // No copy: the clipboard could carry more lines than a prompt of the block reads (R130).
    expect(within(block).queryAllByRole("button")).toHaveLength(0);
    expect(block.textContent).toContain("Organizational unit");
    expect(block.textContent).not.toMatch(/New-ADComputer|Read-Host/);
    fireEvent.click(screen.getByTestId("kerberos-next"));
    // Step 3: the one-time password and the rotation.
    await screen.findByTestId("field-password");
    fireEvent.click(screen.getByTestId("form-submit"));
    expect(screen.getByTestId("field-error").dataset.field).toBe("password");
    input("field-password", "One-Time-Pass-1");
    fireEvent.click(screen.getByTestId("form-submit"));
    const status = await screen.findByTestId("kerberos-status");
    expect(within(status).getByTestId("kerberos-principal").textContent).toBe("TENKO-DNS$@CORP.EXAMPLE.TEST");
    expect(within(status).getByTestId("kerberos-owner").textContent).toContain("only Tenko knows it");
    expect(within(status).getByTestId("kerberos-rotation").textContent).toBe("Every 30 days");
    const versions = within(status).getAllByTestId("kerberos-version");
    expect(versions.map((v) => [v.dataset.kvno, v.dataset.state])).toEqual([["2", "current"]]);
    expect(
      within(status)
        .getAllByTestId("kerberos-spn")
        .map((s) => s.textContent),
    ).toEqual(["DNS/tenko1.corp.example.test", "HTTP/tenko1.corp.example.test"]);
    expect(within(status).getByTestId("kerberos-passed")).toBeTruthy();
    expect(within(status).getByTestId("kerberos-rotate")).toBeTruthy();
    expect(document.body.textContent).not.toContain("One-Time-Pass-1");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("dns_28 shows a refused one-time password and forgets it", async () => {
    open();
    await adoptUntilPassword();
    input("field-password", "wrong");
    fireEvent.click(screen.getByTestId("form-submit"));
    const notice = await screen.findByTestId("error-notice");
    expect(notice.dataset.code).toBe("dns.krb.password.refused");
    expect((screen.getByTestId("field-password") as HTMLInputElement).value).toBe("");
    // An unreachable KDC is its own error.
    fireEvent.click(screen.getByTestId("kerberos-back"));
    fireEvent.click(screen.getByTestId("kerberos-back"));
    input("field-kdcs", "192.0.2.1");
    fireEvent.click(screen.getByTestId("kerberos-next"));
    fireEvent.click(await screen.findByTestId("kerberos-next"));
    await screen.findByTestId("field-password");
    input("field-password", "One-Time-Pass-1");
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(screen.getByTestId("error-notice").dataset.code).toBe("dns.krb.kdc.unreachable"));
  });

  it("dns_28 imports a keytab file and shows the imported account without rotation", async () => {
    open();
    fireEvent.click(await screen.findByTestId("kerberos-choose-import"));
    input("field-realm", "CORP.EXAMPLE.TEST");
    input("field-spns", "DNS/tenko1.corp.example.test");
    fireEvent.click(screen.getByTestId("form-submit"));
    expect(screen.getAllByTestId("field-error").map((e) => e.dataset.field)).toContain("keytab");
    const file = new File([new Uint8Array([0x05, 0x02, 0x00, 0x00, 0x00, 0x10])], "tenko.keytab");
    fireEvent.change(screen.getByTestId("field-keytab"), {
      target: { files: [file] },
    });
    await screen.findByText(/tenko\.keytab is read/);
    fireEvent.click(screen.getByTestId("form-submit"));
    const status = await screen.findByTestId("kerberos-status");
    expect(within(status).getByTestId("kerberos-owner").textContent).toContain("imported from a keytab");
    expect(within(status).getByTestId("kerberos-rotation").textContent).toBe("None");
    expect(
      within(status)
        .getAllByTestId("kerberos-version")
        .map((v) => [v.dataset.kvno, v.dataset.state]),
    ).toEqual([
      ["3", "current"],
      ["2", "previous"],
    ]);
    expect(within(status).queryByTestId("kerberos-rotate")).toBeNull();
  });

  it("dns_28 refuses a file that is not a keytab", async () => {
    open();
    fireEvent.click(await screen.findByTestId("kerberos-choose-import"));
    input("field-realm", "CORP.EXAMPLE.TEST");
    input("field-spns", "DNS/tenko1.corp.example.test");
    fireEvent.change(screen.getByTestId("field-keytab"), {
      target: { files: [new File(["not a keytab"], "notes.txt")] },
    });
    await screen.findByText(/notes\.txt is read/);
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(screen.getByTestId("error-notice").dataset.code).toBe("dns.krb.keytab.invalid"));
  });
});

describe("the Kerberos status", () => {
  it("dns_28 shows each finding with its fix, the versions and the actions", async () => {
    setMockKerberos(account, [
      {
        code: "dns.gss.spn_missing",
        detail: "the KDC knows no account with the SPN DNS/ns2.corp.example.test",
        params: { spn: "DNS/ns2.corp.example.test" },
        at: "2026-11-06T10:00:00Z",
      },
      {
        code: "dns.gss.self_test_failed",
        detail: "the account is disabled or locked",
        params: { reason: "disabled", kdc_error: "18" },
        at: "2026-11-06T10:00:00Z",
      },
      {
        code: "dns.gss.clock_skew",
        detail: "the node's clock is 120 s behind the KDC's",
        params: { skew_secs: "120" },
        at: "2026-11-06T10:00:00Z",
      },
      {
        code: "dns.gss.kvno_unknown",
        detail: "the KDC issues key version 7",
        params: { kvno: "7", held: "3,4" },
        at: "2026-11-06T10:00:00Z",
      },
    ]);
    const view = open();
    const status = await screen.findByTestId("kerberos-status");
    const findings = within(status).getAllByTestId("kerberos-finding");
    expect(findings).toHaveLength(4);
    expect(findings[0]?.textContent).toContain("No account holds DNS/ns2.corp.example.test");
    expect(findings[0]?.textContent).toContain("setspn -S DNS/ns2.corp.example.test");
    expect(findings[0]?.textContent).toContain("the KDC knows no account");
    expect(findings[1]?.textContent).toContain("disabled or locked in Active Directory");
    expect(findings[2]?.textContent).toContain("120 s");
    expect(findings[3]?.textContent).toContain("key version 7, Tenko holds 3,4");
    expect(within(status).queryByTestId("kerberos-passed")).toBeNull();
    expect(
      within(status)
        .getAllByTestId("kerberos-version")
        .map((v) => v.dataset.state),
    ).toEqual(["current", "previous"]);
    expect(within(status).getByTestId("kerberos-next-rotation").textContent).not.toBe("–");
    expect(await axeViolations(view.container)).toEqual([]);
    // Run the self-test: the mock's directory finds nothing now.
    fireEvent.click(within(status).getByTestId("kerberos-check"));
    await waitFor(() => expect(screen.queryAllByTestId("kerberos-finding")).toHaveLength(0));
    // Rotate: a job, and a new current version.
    fireEvent.click(screen.getByTestId("kerberos-rotate"));
    expect(await screen.findByTestId("kerberos-rotation-job")).toBeTruthy();
    await waitFor(() => expect(screen.getAllByTestId("kerberos-version")[0]?.dataset.kvno).toBe("5"));
  });

  it("dns_28 asks before removing the account and then offers the set-up again", async () => {
    setMockKerberos(account);
    open();
    fireEvent.click(await screen.findByTestId("kerberos-delete"));
    const dialog = await screen.findByTestId("dialog-kerberos-delete");
    expect(dialog.textContent).toContain("TENKO-DNS$@CORP.EXAMPLE.TEST");
    expect(dialog.textContent).toContain("The account in Active Directory stays");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    expect(await screen.findByTestId("kerberos-setup")).toBeTruthy();
  });

  it("reads nothing without dns.keys", async () => {
    await signInAlex({ prepare: (u) => (u.roles = ["viewer"]) });
    setMockKerberos(account);
    open();
    expect(await screen.findByTestId("kerberos-no-access")).toBeTruthy();
    expect(screen.queryByTestId("kerberos-status")).toBeNull();
    expect(screen.queryByTestId("kerberos-setup")).toBeNull();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    expect(await screen.findByText("Ställ in kontot för säkra uppdateringar")).toBeTruthy();
    expect(screen.getByTestId("kerberos-choose-adopt").textContent).toBe("Ta över ett förberett konto");
  });
});
