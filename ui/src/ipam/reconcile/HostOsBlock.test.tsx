import { screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HOST_IDS } from "../../api/mock/ipam/api";
import { server } from "../../api/mock/node";
import { paths } from "../../app/paths";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import HostView from "../../hosts/HostView";
import { HostOsBlock } from "./HostOsBlock";

let requests: Record<string, string>[] = [];

beforeEach(async () => {
  requests = [];
  server.events.on("request:start", ({ request }) => {
    const url = new URL(request.url);
    if (url.pathname === "/api/v1/ipam/reconcile") requests.push(Object.fromEntries(url.searchParams));
  });
  await signInAlex();
});

afterEach(() => {
  server.events.removeAllListeners();
  setSessionForTest(null);
});

const problem = (status: number, code: string) =>
  HttpResponse.json({ type: "about:blank", title: "Refused", status, code, detail: "", params: {} }, { status, headers: { "content-type": "application/problem+json" } });

function renderBlock(host: string) {
  return renderRoute(() => <HostOsBlock host={host} />, { url: "/block", path: "/block" });
}

describe("the OS block of the host page", () => {
  it("shows the OS field of the DHCP fingerprint with its confidence, source and truth, and the vendors", async () => {
    const id = HOST_IDS.ha as string;
    const view = renderBlock(id);
    const os = await screen.findByTestId("host-reconcile-os");
    await waitFor(() => expect(within(os).getByTestId("reconcile-os-guess").textContent).toBe("Windows 10 or 11 (or Server 2016 and later) (85 %)"));
    expect(within(os).getByTestId("reconcile-os-source").textContent).toBe("from dhcp:1 (Lease)");
    expect(screen.getByTestId("host-reconcile-vendors").textContent).toBe("MSFT 5.0");
    expect(screen.getByTestId("host-reconcile-link").getAttribute("href")).toBe(`/ipam/reconcile?host=${id}`);
    expect(requests).toEqual([{ host: id, limit: "1" }]);
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows a dash for the OS and the vendors of a host nothing is known about", async () => {
    renderBlock(HOST_IDS.doorbell as string);
    const os = await screen.findByTestId("host-reconcile-os");
    expect(os.textContent).toBe("–");
    expect(screen.getByTestId("host-reconcile-vendors").textContent).toBe("–");
    expect(screen.queryByTestId("reconcile-os")).toBeNull();
  });

  it("lists the guesses besides the one that wins", async () => {
    const winning = { guess: "Debian 12", confidence: 100, source: "inventory:abc", truth: "scan", last_seen: "2026-10-22T10:00:00Z" };
    const other = { guess: "Linux 6.x", confidence: 90, source: "probe:2:os_fingerprint", truth: "scan", last_seen: "2026-10-22T09:00:00Z" };
    server.use(
      http.get("/api/v1/ipam/reconcile", () =>
        HttpResponse.json({
          items: [],
          next_cursor: null,
          revision: 1,
          host: { host: HOST_IDS.ha, name: "ha", mode: "reserved", macs: [], ips: [], os: winning, os_guesses: [winning, other], vendors: ["Example Vendor", "MSFT 5.0"] },
        }),
      ),
    );
    renderBlock(HOST_IDS.ha as string);
    const os = await screen.findByTestId("host-reconcile-os");
    await waitFor(() => expect(within(os).getAllByTestId("reconcile-os-guess").map((e) => e.textContent)).toEqual(["Debian 12 (100 %)", "Linux 6.x (90 %)"]));
    expect(within(os).getAllByTestId("host-reconcile-os-other")).toHaveLength(1);
    expect(screen.getByTestId("host-reconcile-vendors").textContent).toBe("Example Vendor and MSFT 5.0");
  });

  it("shows a quiet note when the view answers 503", async () => {
    server.use(http.get("/api/v1/ipam/reconcile", () => problem(503, "sys.unavailable")));
    renderBlock(HOST_IDS.ha as string);
    expect((await screen.findByTestId("host-os-unavailable")).textContent).toBe("The operating system and vendors are not available right now.");
    expect(screen.queryByTestId("host-reconcile-os")).toBeNull();
    expect(screen.queryByTestId("error-notice")).toBeNull();
  });

  it("shows nothing when the principal may not read the view", async () => {
    server.use(http.get("/api/v1/ipam/reconcile", () => problem(403, "auth.forbidden")));
    renderBlock(HOST_IDS.ha as string);
    await waitFor(() => expect(requests).toHaveLength(1));
    await waitFor(() => expect(screen.queryByTestId("host-os-block")).toBeNull());
    expect(screen.queryByTestId("host-os-unavailable")).toBeNull();
  });
});

describe("the host page", () => {
  it("shows the block in the observation section", async () => {
    renderRoute(HostView, { url: paths.host("ha"), path: "/ipam/hosts/:fqdn" });
    const section = await screen.findByTestId("host-observations");
    expect((await within(section).findByTestId("host-reconcile-os")).textContent).toContain("Windows 10 or 11");
    expect(within(section).getByTestId("host-reconcile-vendors").textContent).toBe("MSFT 5.0");
  });

  it("keeps the rest of the page when the view answers 503", async () => {
    server.use(http.get("/api/v1/ipam/reconcile", () => problem(503, "sys.unavailable")));
    renderRoute(HostView, { url: paths.host("ha"), path: "/ipam/hosts/:fqdn" });
    expect(await screen.findByTestId("host-modes")).toBeTruthy();
    expect(await screen.findByTestId("host-os-unavailable")).toBeTruthy();
    expect(within(screen.getByTestId("host-observations")).getByTestId("host-os-block")).toBeTruthy();
  });
});
