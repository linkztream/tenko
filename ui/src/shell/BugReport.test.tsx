// "Report a bug": the diagnostics are shown before anything leaves the browser, the GitHub
// link carries the template's fields, the copy action puts the same text on the clipboard,
// and under the Hardened profile the link is gone.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SystemDiagnostics } from "../api/types";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { db, signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import {
  BugReportDialog,
  DIAGNOSTICS_LIMIT,
  ISSUE_TEMPLATE,
  ISSUE_URL,
  TRUNCATION_NOTE,
  issueUrl,
  linkAllowed,
  truncateDiagnostics,
} from "./BugReport";

const sample: SystemDiagnostics = {
  version: "0.0.3",
  api_version: "0.0.3",
  os: "linux",
  arch: "x86_64",
  profile: "standard",
  roles: ["controller", "dns"],
  modules: ["ipam", "dns"],
  uptime_seconds: 90_061,
  findings: [{ code: "dns.role.lagging", severity: "warning" }],
  log: ["WARN zone zone-1.example.test lagging"],
  text: "Tenko DDI diagnostics\nversion: 0.0.3\nlog:\n  WARN zone zone-1.example.test lagging\n",
};

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  setSessionForTest(null);
  vi.restoreAllMocks();
});

describe("the issue link", () => {
  it("prefills the template's fields from the document", () => {
    const url = new URL(issueUrl(sample));
    expect(url.origin + url.pathname).toBe(ISSUE_URL);
    expect(url.searchParams.get("template")).toBe(ISSUE_TEMPLATE);
    expect(url.searchParams.get("version")).toBe("tenko 0.0.3");
    expect(url.searchParams.get("profile")).toBe("Standard");
    expect(url.searchParams.get("platform")).toBe("linux x86_64");
    expect(url.searchParams.get("logs")).toBe(sample.text);
  });

  it("cuts the diagnostics at a line boundary with a note to paste the rest", () => {
    const text = Array.from({ length: 400 }, (_, i) => `line ${String(i).padStart(3, "0")} of the diagnostics`).join("\n");
    expect(text.length).toBeGreaterThan(DIAGNOSTICS_LIMIT);
    const cut = truncateDiagnostics(text);
    expect(cut.length).toBeLessThanOrEqual(DIAGNOSTICS_LIMIT);
    expect(cut.endsWith(`\n${TRUNCATION_NOTE}`)).toBe(true);
    const body = cut.slice(0, cut.length - TRUNCATION_NOTE.length - 1);
    expect(body.endsWith("of the diagnostics")).toBe(true);
    expect(truncateDiagnostics("short")).toBe("short");
    expect(new URL(issueUrl({ ...sample, text })).searchParams.get("logs")).toBe(cut);
  });

  it("is allowed in every profile but Hardened", () => {
    expect(linkAllowed({ profile: "home" })).toBe(true);
    expect(linkAllowed({ profile: "lab" })).toBe(true);
    expect(linkAllowed({ profile: "hardened" })).toBe(false);
  });
});

describe("the dialog", () => {
  it("shows the diagnostics text, the account line and both actions", async () => {
    renderRoute(() => <BugReportDialog onClose={() => {}} />);
    const dialog = await screen.findByTestId("dialog-bug-report");
    const text = await within(dialog).findByTestId("report-text");
    expect(text.textContent).toContain("Tenko DDI diagnostics");
    expect(text.textContent).toContain("profile: standard");
    expect(text.textContent).toContain("zone-1.example.test");
    expect(within(dialog).getByTestId("report-account")).toBeTruthy();
    const open = within(dialog).getByTestId("report-open") as HTMLAnchorElement;
    expect(open.getAttribute("target")).toBe("_blank");
    expect(open.getAttribute("rel")).toContain("noopener");
    const url = new URL(open.href);
    expect(url.origin + url.pathname).toBe(ISSUE_URL);
    expect(url.searchParams.get("template")).toBe(ISSUE_TEMPLATE);
    expect(url.searchParams.get("logs")).toBe(text.textContent);
    expect(within(dialog).getByTestId("report-copy")).toBeTruthy();
    expect(await axeViolations()).toEqual([]);
  });

  it("copies the same text to the clipboard", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    renderRoute(() => <BugReportDialog onClose={() => {}} />);
    const dialog = await screen.findByTestId("dialog-bug-report");
    const text = await within(dialog).findByTestId("report-text");
    fireEvent.click(within(dialog).getByTestId("report-copy"));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(writeText).toHaveBeenCalledWith(text.textContent);
  });

  it("offers copy only under the Hardened profile and says why", async () => {
    db.settings.profile = "hardened";
    renderRoute(() => <BugReportDialog onClose={() => {}} />);
    const dialog = await screen.findByTestId("dialog-bug-report");
    await within(dialog).findByTestId("report-text");
    expect(within(dialog).queryByTestId("report-open")).toBeNull();
    expect(within(dialog).queryByTestId("report-account")).toBeNull();
    expect(within(dialog).getByTestId("report-hardened").textContent).toContain("Hardened");
    expect(within(dialog).getByTestId("report-copy").className).toContain("primary");
    expect(await axeViolations()).toEqual([]);
  });

  it("closes from its close button", async () => {
    const onClose = vi.fn();
    renderRoute(() => <BugReportDialog onClose={onClose} />);
    const dialog = await screen.findByTestId("dialog-bug-report");
    fireEvent.click(within(dialog).getByTestId("report-close"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
