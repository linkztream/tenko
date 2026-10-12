import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { db } from "../../api/mock/db";
import { auditExportState } from "../../api/mock/routes-audit-export";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { setSessionForTest } from "../../auth/session";
import { signInAs } from "../testkit";
import AuditExportPage from "./AuditExportPage";
import { defaultPort, lag, newSink, sinkProblems, sinkTarget } from "./model";

const NO_SHELL = { disable: ["region"] } as const;

beforeEach(async () => {
  await signInAs();
});

afterEach(() => setSessionForTest(null));

async function openPage() {
  const view = renderRoute(AuditExportPage, { url: "/settings/audit-export", path: "/settings/audit-export" });
  await screen.findByTestId("audit-export-sinks");
  return view;
}

/** Fills the sink dialog for a syslog receiver. */
function fill(dialog: HTMLElement, name: string, host: string) {
  fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: name } });
  fireEvent.input(within(dialog).getByTestId("field-host"), { target: { value: host } });
}

describe("the audit export page", () => {
  it("starts without sinks and adds one over TLS after a test record", async () => {
    await openPage();
    expect(await screen.findByTestId("audit-export-empty")).toBeTruthy();
    fireEvent.click(screen.getByTestId("audit-export-add"));
    const dialog = await screen.findByTestId("dialog-audit-sink");
    // TLS on 6514 in RFC 5424 is the default sink (S3-Q6).
    expect((within(dialog).getByTestId("field-transport-tls") as HTMLInputElement).checked).toBe(true);
    expect((within(dialog).getByTestId("field-port") as HTMLInputElement).value).toBe("6514");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("Enter a name.")).toBeTruthy();
    expect(within(dialog).getByText("Enter the host name or address of the receiver.")).toBeTruthy();

    fill(dialog, "SIEM", "syslog.example.test");
    fireEvent.click(within(dialog).getByTestId("audit-export-test"));
    const result = await within(dialog).findByTestId("audit-export-test-result");
    expect(result.dataset.delivered).toBe("true");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-audit-sink")).toBeNull());

    expect(auditExportState.sinks).toHaveLength(1);
    expect(auditExportState.sinks[0]).toMatchObject({ name: "SIEM", transport: "tls", format: "rfc5424", host: "syslog.example.test", port: 6514 });
    const row = await screen.findByTestId("audit-export-sink");
    expect(row.dataset.state).toBe("ok");
    expect(row.textContent).toContain("syslog.example.test:6514");
    expect(within(row).getByTestId("audit-export-lag").textContent).toBe("0");
  });

  it("shows a failing sink with its lag, and a failed test record", async () => {
    auditExportState.sinks = [{ ...newSink("s1"), name: "Down", host: "unreachable.example.test" }];
    await openPage();
    const row = await screen.findByTestId("audit-export-sink");
    expect(row.dataset.state).toBe("failing");
    expect(row.textContent).toContain("connection refused");
    expect(within(row).getByTestId("audit-export-lag").textContent).toBe("12");
    fireEvent.click(within(row).getByTestId("audit-export-edit"));
    const dialog = await screen.findByTestId("dialog-audit-sink");
    fireEvent.click(within(dialog).getByTestId("audit-export-test"));
    const result = await within(dialog).findByTestId("audit-export-test-result");
    expect(result.dataset.delivered).toBe("false");
    expect(result.textContent).toContain("connection refused");
  });

  it("switches to a file sink in JSON and pauses and removes a sink", async () => {
    await openPage();
    await screen.findByTestId("audit-export-empty");
    fireEvent.click(screen.getByTestId("audit-export-add"));
    const dialog = await screen.findByTestId("dialog-audit-sink");
    fireEvent.click(within(dialog).getByTestId("field-transport-file"));
    expect((within(dialog).getByTestId("field-format") as HTMLSelectElement).value).toBe("json");
    expect(within(dialog).queryByTestId("field-host")).toBeNull();
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Shipper" } });
    fireEvent.input(within(dialog).getByTestId("field-path"), { target: { value: "/var/log/tenko/audit.jsonl" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const row = await screen.findByTestId("audit-export-sink");
    expect(auditExportState.sinks[0]).toMatchObject({ transport: "file", format: "json", path: "/var/log/tenko/audit.jsonl" });

    fireEvent.click(within(row).getByTestId("audit-export-toggle"));
    await waitFor(() => expect(screen.getByTestId("audit-export-sink").dataset.state).toBe("disabled"));
    fireEvent.click(within(screen.getByTestId("audit-export-sink")).getByTestId("audit-export-remove"));
    fireEvent.click(within(await screen.findByTestId("dialog-confirm")).getByTestId("confirm-ok"));
    await waitFor(() => expect(auditExportState.sinks).toHaveLength(0));
  });

  it("warns in the Hardened profile while no sink delivers (TGL-21)", async () => {
    db.settings.profile = "hardened";
    await openPage();
    expect((await screen.findByTestId("audit-export-required")).textContent).toContain("TGL-21");
  });

  it("has no accessibility violations on the page and in the dialog", async () => {
    auditExportState.sinks = [{ ...newSink("s1"), name: "SIEM", host: "syslog.example.test" }];
    const view = await openPage();
    await screen.findByTestId("audit-export-sink");
    expect(await axeViolations(view.container)).toEqual([]);
    fireEvent.click(screen.getByTestId("audit-export-add"));
    await screen.findByTestId("dialog-audit-sink");
    expect(await axeViolations(document.body, NO_SHELL)).toEqual([]);
  });
});

describe("the sink model", () => {
  it("knows the syslog ports, the target and the lag", () => {
    expect(defaultPort("tls")).toBe(6514);
    expect(defaultPort("udp")).toBe(514);
    expect(sinkTarget({ ...newSink("x"), host: "h.example.test", port: 514 })).toBe("h.example.test:514");
    expect(sinkTarget({ ...newSink("x"), transport: "file", path: "/a" })).toBe("/a");
    expect(lag({ state: "ok", cursor: 5, head: 9 })).toBe(4);
    expect(lag({ state: "ok", cursor: 9, head: 5 })).toBe(0);
    expect(sinkProblems({ ...newSink("x"), name: "a", host: "h", port: 70000 })).toHaveProperty("port");
  });
});
