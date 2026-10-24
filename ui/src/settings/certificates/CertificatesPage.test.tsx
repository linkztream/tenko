import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { db } from "../../api/mock/db";
import { server } from "../../api/mock/node";
import { tlsState } from "../../api/mock/routes-tls";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { signInAs } from "../testkit";
import CertificatesPage from "./CertificatesPage";
import { groupedFingerprint, noticeKind, profileRule, stateClass } from "./model";

const NO_SHELL = { disable: ["region"] } as const;

beforeEach(async () => {
  await setLocale("en");
  await signInAs();
});

afterEach(() => setSessionForTest(null));

async function openPage() {
  const view = renderRoute(CertificatesPage, { url: "/settings/certificates", path: "/settings/certificates" });
  await screen.findByTestId("certificates-mode");
  return view;
}

/** The installation as set up with `mode`, under `profile`. */
function arrange(mode: "internal_ca" | "imported" | "reverse_proxy" | "plain", profile = db.settings.profile) {
  db.installation.tls.mode = mode;
  db.installation.tls.trusted_proxies = ["198.51.100.0/24", "203.0.113.7"];
  db.settings.profile = profile;
}

const text = (testid: string) => screen.getByTestId(testid).textContent;

describe("the certificates page", () => {
  it("shows the internal CA's certificate, its names, chain and fingerprint, and the CA root download", async () => {
    await openPage();
    expect(screen.getByTestId("certificates-mode").dataset.mode).toBe("internal_ca");
    expect(text("certificates-mode-name")).toContain("Internal certificate authority");
    expect(text("certificates-min-version")).toBe("TLS 1.2");
    expect(text("certificates-hsts")).toBe("On");
    expect(text("cert-subject")).toBe(`CN=${db.installation.host_name}`);
    expect(text("cert-names")).toContain("192.0.2.10");
    expect(text("cert-issuer")).toBe("CN=Tenko Internal CA");
    expect(text("cert-chain")).toBe("1 certificate");
    expect(text("cert-fingerprint")).toBe(groupedFingerprint("7c1f3a9e5b2d4086a3c1e9d8f7b6a5c4d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7"));
    expect(text("cert-days")).toBe("62 days");
    expect(screen.getByTestId("cert-days").className).toBe("tag");
    expect(text("ca-subject")).toBe("CN=Tenko Internal CA");
    const link = screen.getByTestId("ca-root-download");
    expect(link.getAttribute("href")).toBe("/api/v1/system/ca-root");
    expect(screen.queryByTestId("certificates-expiring")).toBeNull();
    expect(screen.queryByTestId("certificates-pending")).toBeNull();
    expect(screen.queryByTestId("certificates-imported")).toBeNull();
  });

  it("shows the days left in the warning style under 30 days, with the expiring warning", async () => {
    tlsState.daysLeft = 12;
    await openPage();
    const days = screen.getByTestId("cert-days");
    expect(days.textContent).toBe("12 days");
    expect(days.classList.contains("discrepancy")).toBe(true);
    const notice = screen.getByTestId("certificates-expiring");
    expect(notice.classList.contains("warn")).toBe(true);
    expect(notice.getAttribute("data-code")).toBe("sys.tls.certificate_expiry");
    expect(notice.textContent).toContain("expires in 12 days");
  });

  it("shows a certificate under 7 days and an expired one in the error style", async () => {
    tlsState.daysLeft = 3;
    const view = await openPage();
    expect(screen.getByTestId("cert-days").classList.contains("conflict")).toBe(true);
    expect(screen.getByTestId("certificates-expiring").classList.contains("bad")).toBe(true);
    view.unmount();

    tlsState.daysLeft = -2;
    await openPage();
    expect(text("cert-days")).toBe("-2 days");
    expect(text("certificates-expiring")).toContain("expired on");
  });

  it("keeps the expiring style off a certificate with 30 days or more", async () => {
    tlsState.daysLeft = 30;
    await openPage();
    expect(screen.getByTestId("cert-days").className).toBe("tag");
    expect(screen.queryByTestId("certificates-expiring")).toBeNull();
  });

  it("describes imported files and what each profile allows for a replaced certificate", async () => {
    const rules: Record<"lab" | "home" | "standard" | "hardened", { accepted: boolean; rule: string }> = {
      lab: { accepted: true, rule: "Lab profile: a certificate replaced in the files is loaded within seconds." },
      home: { accepted: true, rule: "Home profile: a certificate replaced in the files is loaded within seconds." },
      standard: { accepted: false, rule: "Standard profile: off unless you set tls.accept_external_replacement = true." },
      hardened: { accepted: false, rule: "Hardened profile: never." },
    };
    for (const [profile, expected] of Object.entries(rules) as [keyof typeof rules, (typeof rules)[keyof typeof rules]][]) {
      arrange("imported", profile);
      const view = await openPage();
      expect(text("imported-cert-path")).toBe("/etc/tenko/tls/fullchain.pem");
      expect(text("imported-key-path")).toBe("/etc/tenko/tls/privkey.pem");
      expect(text("imported-interval")).toBe("every 5 s");
      expect(text("cert-chain")).toBe("2 certificates");
      expect(text("cert-issuer")).toBe("CN=Example Issuing CA R1");
      const accept = screen.getByTestId("imported-accept");
      expect(accept.dataset.accepted, profile).toBe(String(expected.accepted));
      expect(accept.textContent).toBe(expected.accepted ? "Accepted" : "Not accepted");
      expect(text("imported-rule"), profile).toContain(expected.rule);
      expect(screen.queryByTestId("ca-root-download")).toBeNull();
      view.unmount();
    }
  });

  it("shows the opt-in of the Standard profile, and Hardened that never accepts", async () => {
    tlsState.accept = true;
    arrange("imported", "standard");
    const view = await openPage();
    expect(screen.getByTestId("imported-accept").dataset.accepted).toBe("true");
    view.unmount();

    arrange("imported", "hardened");
    await openPage();
    expect(screen.getByTestId("imported-accept").dataset.accepted).toBe("false");
    expect(text("certificates-min-version")).toBe("TLS 1.3");
  });

  it("names a newer certificate on disk as pending until the next restart", async () => {
    arrange("imported", "standard");
    tlsState.pending = true;
    await openPage();
    const notice = screen.getByTestId("certificates-pending-notice");
    expect(notice.getAttribute("data-code")).toBe("sys.tls.certificate_pending");
    expect(notice.textContent).toContain("restart Tenko to apply it");
    const pending = screen.getByTestId("certificates-pending");
    expect(within(pending).getByTestId("pending-fingerprint").textContent).toBe(
      groupedFingerprint("b4e2a1d09c8f7e6d5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f"),
    );
    expect(within(pending).getByTestId("pending-days").textContent).toBe("90 days");
    // The certificate in use is still the old one.
    expect(text("cert-fingerprint")).toBe(groupedFingerprint("7c1f3a9e5b2d4086a3c1e9d8f7b6a5c4d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7"));
  });

  it("shows a failed reload and a missing certificate", async () => {
    arrange("imported");
    tlsState.lastError = "the private key does not match the certificate";
    await openPage();
    expect(text("certificates-error")).toContain("the private key does not match the certificate");
  });

  it("shows the proxies and the public host of a reverse proxy, and no certificate", async () => {
    arrange("reverse_proxy");
    await openPage();
    expect(text("proxy-host")).toBe(db.installation.host_name);
    expect(screen.getByTestId("proxy-trusted").textContent).toBe("198.51.100.0/24203.0.113.7");
    expect(text("proxy-protocol")).toBe("Off");
    expect(screen.queryByTestId("certificates-served")).toBeNull();
    expect(screen.queryByTestId("certificates-min-version")).toBeNull();
  });

  it("warns about plain HTTP", async () => {
    arrange("plain", "lab");
    await openPage();
    expect(text("certificates-plain")).toContain("Plain HTTP is accepted from every source");
    expect(text("certificates-hsts")).toBe("Off");
    expect(screen.queryByTestId("certificates-served")).toBeNull();
  });

  it("reads once when it opens and again only when Refresh is pressed", async () => {
    let reads = 0;
    server.use(
      http.get("/api/v1/system/tls", () => {
        reads += 1;
        return HttpResponse.json({
          mode: "reverse_proxy",
          hsts: true,
          min_version: null,
          certificate: null,
          loaded_at: null,
          last_error: null,
          pending: null,
          reverse_proxy: { trusted_proxies: ["198.51.100.0/24"], proxy_protocol: reads > 1, public_host: "ddi.example.test" },
        });
      }),
    );
    await openPage();
    expect(reads).toBe(1);
    expect(text("proxy-protocol")).toBe("Off");
    // Nothing reads on its own.
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(reads).toBe(1);

    fireEvent.click(screen.getByTestId("certificates-refresh"));
    await waitFor(() => expect(text("proxy-protocol")).toBe("On"));
    expect(reads).toBe(2);
    expect(screen.getByTestId("certificates-read-at").textContent).toMatch(/^Read /);
  });

  it("still words the page when the security settings cannot be read", async () => {
    arrange("imported");
    server.use(http.get("/api/v1/settings/security", () => HttpResponse.json({}, { status: 500 })));
    await openPage();
    expect(text("imported-rule")).toContain("The security profile could not be read");
  });

  it("shows the problem when the listener is not running", async () => {
    server.use(
      http.get("/api/v1/system/tls", () =>
        HttpResponse.json(
          { type: "about:blank", status: 503, code: "sys.not_ready", title: "x", detail: "x", params: { reason: "starting" } },
          { status: 503, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    renderRoute(CertificatesPage, { url: "/settings/certificates", path: "/settings/certificates" });
    const notice = await screen.findByTestId("error-notice");
    expect(notice.getAttribute("data-code")).toBe("sys.not_ready");
  });

  it("has no accessibility violations and works in Swedish", async () => {
    arrange("imported", "standard");
    tlsState.pending = true;
    tlsState.daysLeft = 12;
    const view = await openPage();
    expect(await axeViolations(view.container, NO_SHELL)).toEqual([]);
    await setLocale("sv");
    await waitFor(() => expect(screen.getByTestId("page-certificates").textContent).toContain("Certifikat som används"));
    expect(text("cert-days")).toBe("12 dagar");
    expect(text("imported-accept")).toBe("Godtas inte");
    expect(text("imported-rule")).toContain("Profilen Standard:");
    expect(text("certificates-pending-notice")).toContain("Starta om Tenko");
    expect(text("certificates-expiring")).toContain("går ut om 12 dagar");
  });
});

describe("the certificates model", () => {
  it("styles the days left by their state", () => {
    expect(stateClass("valid")).toBe("");
    expect(stateClass("warning")).toBe("discrepancy");
    for (const state of ["critical", "expired", "not_yet_valid"] as const) expect(stateClass(state)).toBe("conflict");
    expect(noticeKind("warning")).toBe("warn");
    expect(noticeKind("critical")).toBe("bad");
    expect(noticeKind("expired")).toBe("bad");
  });

  it("names a rule for every profile", () => {
    expect(new Set((["lab", "home", "standard", "hardened"] as const).map(profileRule)).size).toBe(4);
  });

  it("groups a fingerprint in eight digits", () => {
    expect(groupedFingerprint("0123456789abcdef0123")).toBe("01234567 89abcdef 0123");
    expect(groupedFingerprint("")).toBe("");
  });
});
