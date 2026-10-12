import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { components } from "../../api/generated/schema";
import { db } from "../../api/mock/db";
import { auditExportState } from "../../api/mock/routes-audit-export";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { setSessionForTest } from "../../auth/session";
import { signInAs } from "../testkit";
import AuditExportPage from "./AuditExportPage";
import { defaultPort, formOf, formProblems, lag, newForm, sameAsStored, sinkTarget, specOf, withChoice, type SinkState } from "./model";

type Sink = components["schemas"]["Sink"];

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

let counter = 0;
/** A stored syslog sink; the host decides the state the mock shows. */
function syslog(name: string, host: string, extra: Partial<Sink> = {}): Sink {
  counter += 1;
  return {
    id: `00000000-0000-4000-8000-${String(counter).padStart(12, "0")}`,
    name,
    enabled: true,
    format: "rfc5424",
    target: { kind: "syslog", transport: "tls", host, port: 6514, facility: "authpriv", tls: {} },
    ...extra,
  };
}

function fileSink(name: string, file: string): Sink {
  counter += 1;
  return {
    id: `00000000-0000-4000-8000-${String(counter).padStart(12, "0")}`,
    name,
    enabled: true,
    format: "json",
    target: { kind: "file", file, max_bytes: 64 * 1024 * 1024, keep: 10 },
  };
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
    expect((within(dialog).getByTestId("field-facility") as HTMLSelectElement).value).toBe("authpriv");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("Enter a name.")).toBeTruthy();
    expect(within(dialog).getByText("Enter the host name or address of the receiver.")).toBeTruthy();

    fill(dialog, "SIEM", "syslog.example.test");
    fireEvent.input(within(dialog).getByTestId("field-server_name"), { target: { value: "siem.example.test" } });
    fireEvent.click(within(dialog).getByTestId("audit-export-test"));
    const result = await within(dialog).findByTestId("audit-export-test-result");
    expect(result.dataset.delivered).toBe("true");
    expect(result.textContent).toContain("12 ms");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-audit-sink")).toBeNull());

    expect(auditExportState.sinks).toHaveLength(1);
    const stored = auditExportState.sinks[0]!;
    expect(stored.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(stored).toMatchObject({
      name: "SIEM",
      format: "rfc5424",
      enabled: true,
      target: { kind: "syslog", transport: "tls", host: "syslog.example.test", port: 6514, tls: { server_name: "siem.example.test" } },
    });
    const row = await screen.findByTestId("audit-export-sink");
    expect(row.dataset.state).toBe("ok");
    expect(row.textContent).toContain("syslog.example.test:6514");
    expect(within(row).getByTestId("audit-export-lag").textContent).toBe("0");
    expect(within(row).getByTestId("audit-export-checkpoint").textContent).toContain("checkpoint at record");
  });

  it("shows all six states with their delivered position, lag, error and checkpoint", async () => {
    auditExportState.sinks = [
      syslog("Idle", "pending.example.test"),
      syslog("Good", "syslog.example.test"),
      syslog("Slow", "behind.example.test"),
      syslog("Flaky", "flaky.example.test"),
      syslog("Down", "unreachable.example.test"),
      syslog("Off", "off.example.test", { enabled: false }),
    ];
    await openPage();
    await waitFor(() => expect(screen.getAllByTestId("audit-export-sink")).toHaveLength(6));
    const rows = Object.fromEntries(screen.getAllByTestId("audit-export-sink").map((row) => [row.dataset.key!, row]));
    const expected: Record<string, SinkState> = { Idle: "pending", Good: "ok", Slow: "behind", Flaky: "failing", Down: "alarm", Off: "disabled" };
    for (const [name, state] of Object.entries(expected)) {
      expect(rows[name]!.dataset.state).toBe(state);
      expect(within(rows[name]!).getByTestId("audit-export-state").dataset.state).toBe(state);
    }
    expect(within(rows.Idle!).getByTestId("audit-export-state").textContent).toBe("Not started");
    expect(within(rows.Good!).getByTestId("audit-export-state").textContent).toBe("Delivering");
    expect(within(rows.Slow!).getByTestId("audit-export-state").textContent).toBe("Falling behind");
    expect(within(rows.Flaky!).getByTestId("audit-export-state").textContent).toBe("Failing");
    expect(within(rows.Down!).getByTestId("audit-export-state").textContent).toBe("Alarm");
    expect(within(rows.Off!).getByTestId("audit-export-state").textContent).toBe("Paused");

    const down = rows.Down!;
    expect(within(down).getByTestId("audit-export-error").dataset.code).toBe("audit.export.connect");
    expect(within(down).getByTestId("audit-export-error").textContent).toContain("connection refused");
    expect(within(down).getByTestId("audit-export-lag").textContent).toBe(String(Math.min(12, db.revision)));
    expect(within(rows.Good!).queryByTestId("audit-export-error")).toBeNull();
    expect(within(rows.Good!).getByTestId("audit-export-last-success")).toBeTruthy();
    expect(within(rows.Good!).getByTestId("audit-export-delivered").textContent).toBe(String(db.revision));
    // The alarm and the backlog raise the status warning.
    const warning = await screen.findByTestId("audit-export-warning");
    expect(warning.dataset.code).toBe("audit.export.failing");
    expect(warning.textContent).toContain("Slow");
    expect(warning.textContent).toContain("Down");
  });

  it("sends a stored sink by id and shows a failed test with its error and elapsed time", async () => {
    auditExportState.sinks = [syslog("Down", "unreachable.example.test")];
    await openPage();
    const row = await screen.findByTestId("audit-export-sink");
    fireEvent.click(within(row).getByTestId("audit-export-edit"));
    const dialog = await screen.findByTestId("dialog-audit-sink");
    expect((within(dialog).getByTestId("field-host") as HTMLInputElement).value).toBe("unreachable.example.test");
    fireEvent.click(within(dialog).getByTestId("audit-export-test"));
    const result = await within(dialog).findByTestId("audit-export-test-result");
    expect(result.dataset.delivered).toBe("false");
    expect(result.dataset.code).toBe("audit.export.connect");
    expect(result.textContent).toContain("connection refused");
    expect(result.textContent).toContain("1,003 ms");
  });

  it("edits a syslog sink over UDP: no TLS fields, the default port follows the transport", async () => {
    auditExportState.sinks = [syslog("SIEM", "syslog.example.test")];
    await openPage();
    fireEvent.click(within(await screen.findByTestId("audit-export-sink")).getByTestId("audit-export-edit"));
    const dialog = await screen.findByTestId("dialog-audit-sink");
    expect(within(dialog).getByTestId("field-ca_pem")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("field-transport-udp"));
    expect((within(dialog).getByTestId("field-port") as HTMLInputElement).value).toBe("514");
    expect(within(dialog).queryByTestId("field-ca_pem")).toBeNull();
    expect(within(dialog).getByText(/UDP has no delivery receipt/)).toBeTruthy();
    fireEvent.change(within(dialog).getByTestId("field-facility"), { target: { value: "local3" } });
    fireEvent.change(within(dialog).getByTestId("field-format"), { target: { value: "cef" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-audit-sink")).toBeNull());
    expect(auditExportState.sinks).toHaveLength(1);
    expect(auditExportState.sinks[0]).toMatchObject({
      format: "cef",
      target: { kind: "syslog", transport: "udp", host: "syslog.example.test", port: 514, facility: "local3", tls: {} },
    });
  });

  it("tests an unsaved form with its spec and validates the TLS client pair", async () => {
    await openPage();
    await screen.findByTestId("audit-export-empty");
    fireEvent.click(screen.getByTestId("audit-export-add"));
    const dialog = await screen.findByTestId("dialog-audit-sink");
    fill(dialog, "Down", "unreachable.example.test");
    // A client certificate without the secret that holds its key is refused before any request.
    fireEvent.input(within(dialog).getByTestId("field-client_cert_pem"), { target: { value: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----" } });
    fireEvent.click(within(dialog).getByTestId("audit-export-test"));
    expect(await within(dialog).findByText(/certificate and the id of the secret/)).toBeTruthy();
    expect(within(dialog).queryByTestId("audit-export-test-result")).toBeNull();
    fireEvent.input(within(dialog).getByTestId("field-client_cert_pem"), { target: { value: "" } });
    fireEvent.click(within(dialog).getByTestId("audit-export-test"));
    const result = await within(dialog).findByTestId("audit-export-test-result");
    expect(result.dataset.delivered).toBe("false");
    // The unsaved sink is not stored by a test.
    expect(auditExportState.sinks).toHaveLength(0);
  });

  it("shows the field errors of the server in the form", async () => {
    await openPage();
    await screen.findByTestId("audit-export-empty");
    fireEvent.click(screen.getByTestId("audit-export-add"));
    const dialog = await screen.findByTestId("dialog-audit-sink");
    // A name and a host that pass the form's check but not the server's: a label with a space.
    fill(dialog, "SIEM", "bad host");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText("Enter a host name or an IPv4 or IPv6 address.")).toBeTruthy();
    expect(within(dialog).getByTestId("field-host").getAttribute("aria-invalid")).toBe("true");
    expect(auditExportState.sinks).toHaveLength(0);
  });

  it("adds a file sink, sets its rotation, then pauses and removes it", async () => {
    await openPage();
    await screen.findByTestId("audit-export-empty");
    fireEvent.click(screen.getByTestId("audit-export-add"));
    const dialog = await screen.findByTestId("dialog-audit-sink");
    fireEvent.click(within(dialog).getByTestId("field-transport-file"));
    expect((within(dialog).getByTestId("field-format") as HTMLSelectElement).value).toBe("json");
    expect(within(dialog).queryByTestId("field-host")).toBeNull();
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Shipper" } });
    fireEvent.input(within(dialog).getByTestId("field-file"), { target: { value: "../audit.jsonl" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByText(/Enter a plain file name/)).toBeTruthy();
    fireEvent.input(within(dialog).getByTestId("field-file"), { target: { value: "audit.jsonl" } });
    fireEvent.input(within(dialog).getByTestId("field-max_mib"), { target: { value: "16" } });
    fireEvent.input(within(dialog).getByTestId("field-keep"), { target: { value: "3" } });
    fireEvent.click(within(dialog).getByTestId("audit-export-test"));
    expect((await within(dialog).findByTestId("audit-export-test-result")).dataset.delivered).toBe("true");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const row = await screen.findByTestId("audit-export-sink");
    expect(auditExportState.sinks[0]).toMatchObject({
      format: "json",
      target: { kind: "file", file: "audit.jsonl", max_bytes: 16 * 1024 * 1024, keep: 3 },
    });
    expect(row.textContent).toContain("audit.jsonl");

    fireEvent.click(within(row).getByTestId("audit-export-toggle"));
    await waitFor(() => expect(screen.getByTestId("audit-export-sink").dataset.state).toBe("disabled"));
    expect(auditExportState.sinks[0]?.enabled).toBe(false);
    fireEvent.click(within(screen.getByTestId("audit-export-sink")).getByTestId("audit-export-remove"));
    fireEvent.click(within(await screen.findByTestId("dialog-confirm")).getByTestId("confirm-ok"));
    await waitFor(() => expect(auditExportState.sinks).toHaveLength(0));
  });

  it("shows the policy and the required warning while no sink is enabled (TGL-21)", async () => {
    db.settings.profile = "hardened";
    db.settings.audit_export = "required";
    await openPage();
    expect((await screen.findByTestId("audit-export-required")).textContent).toContain("TGL-21");
    expect(screen.getByTestId("audit-export-warning").dataset.code).toBe("audit.export.required");
    const policy = await screen.findByTestId("audit-export-policy");
    expect(policy.dataset.required).toBe("true");
    expect(policy.dataset.satisfied).toBe("false");
    expect(policy.textContent).toContain("not met");
  });

  it("meets the policy with a sink, and refuses to remove the last one", async () => {
    db.settings.profile = "hardened";
    db.settings.audit_export = "required";
    auditExportState.sinks = [syslog("SIEM", "syslog.example.test")];
    await openPage();
    const policy = await screen.findByTestId("audit-export-policy");
    expect(policy.dataset.satisfied).toBe("true");
    expect(screen.queryByTestId("audit-export-required")).toBeNull();
    fireEvent.click(await screen.findByTestId("audit-export-remove"));
    const confirm = await screen.findByTestId("dialog-confirm");
    expect(confirm.textContent).toContain("the server refuses to remove it");
    fireEvent.click(within(confirm).getByTestId("confirm-ok"));
    // The server refuses (audit.export.required) with the administrator's remedy in words.
    expect(await within(confirm).findByText(/Enable an export sink first/)).toBeTruthy();
    expect(auditExportState.sinks).toHaveLength(1);
  });

  it("saves the alarm delay with the sinks unchanged", async () => {
    auditExportState.sinks = [syslog("SIEM", "syslog.example.test")];
    await openPage();
    const input = (await screen.findByTestId("field-alert_after_secs")) as HTMLInputElement;
    expect(input.value).toBe("300");
    fireEvent.input(input, { target: { value: "5" } });
    fireEvent.click(screen.getByTestId("audit-export-alert-save"));
    expect(await screen.findByText(/Enter a whole number of seconds/)).toBeTruthy();
    fireEvent.input(input, { target: { value: "600" } });
    fireEvent.click(screen.getByTestId("audit-export-alert-save"));
    await waitFor(() => expect(auditExportState.alert_after_secs).toBe(600));
    expect(auditExportState.sinks).toHaveLength(1);
  });

  it("reloads on a stale revision (If-Match) and keeps the other editor's change", async () => {
    auditExportState.sinks = [syslog("SIEM", "syslog.example.test")];
    await openPage();
    const row = await screen.findByTestId("audit-export-sink");
    // Someone else adds a sink after the page was read.
    const other = fileSink("Other", "other.jsonl");
    auditExportState.sinks = [...auditExportState.sinks, other];
    auditExportState.revision += 1;
    fireEvent.click(within(row).getByTestId("audit-export-toggle"));
    expect((await screen.findByTestId("error-notice")).dataset.code).toBe("audit.export.conflict");
    // The write was refused: neither the toggle nor a lost sink.
    expect(auditExportState.sinks.map((s) => s.name)).toEqual(["SIEM", "Other"]);
    expect(auditExportState.sinks[0]?.enabled).toBe(true);
    await waitFor(() => expect(screen.getAllByTestId("audit-export-sink")).toHaveLength(2));
    // After the reload the same action succeeds.
    fireEvent.click(within(screen.getAllByTestId("audit-export-sink")[0]!).getByTestId("audit-export-toggle"));
    await waitFor(() => expect(auditExportState.sinks[0]?.enabled).toBe(false));
    expect(auditExportState.sinks).toHaveLength(2);
  });

  it("has no accessibility violations on the page and in the dialog", async () => {
    auditExportState.sinks = [syslog("SIEM", "syslog.example.test"), syslog("Down", "unreachable.example.test")];
    const view = await openPage();
    await waitFor(() => expect(screen.getAllByTestId("audit-export-sink")).toHaveLength(2));
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
    expect(sinkTarget(syslog("a", "h.example.test"))).toBe("h.example.test:6514");
    expect(sinkTarget(fileSink("a", "audit.jsonl"))).toBe("audit.jsonl");
    const status = { state: "ok", delivered: { seq: 5, hash: "" }, lag: 4 } as const;
    expect(lag(status)).toBe(4);
    expect(lag({ ...status, lag: -1 })).toBe(0);
    expect(formProblems({ ...newForm(), name: "a", host: "h", port: "70000" })).toHaveProperty("port");
    expect(formProblems({ ...withChoice(newForm(), "file"), name: "a", file: ".hidden" })).toHaveProperty("file");
    expect(formProblems({ ...withChoice(newForm(), "file"), name: "a", file: "a.log", max_mib: "0.01" })).toHaveProperty("max_mib");
  });

  it("converts between a form and a SinkSpec without losing a field", () => {
    const sink: Sink = {
      ...syslog("SIEM", "syslog.example.test"),
      target: {
        kind: "syslog",
        transport: "tls",
        host: "syslog.example.test",
        port: 6515,
        facility: "local1",
        tls: { ca_pem: "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----", server_name: "siem.example.test", client_cert_pem: "-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----", client_key: "00000000-0000-4000-8000-0000000000aa" },
      },
    };
    const spec = specOf(formOf(sink));
    expect(spec).toMatchObject({ id: sink.id, name: "SIEM", enabled: true, format: "rfc5424", target: sink.target });
    expect(sameAsStored(formOf(sink), sink)).toBe(true);
    expect(sameAsStored({ ...formOf(sink), host: "other.example.test" }, sink)).toBe(false);
    // A new sink carries no id; a file sink carries its rotation.
    expect(specOf({ ...newForm(), name: "N", host: "h.example.test" })).not.toHaveProperty("id");
    expect(specOf({ ...withChoice(newForm(), "file"), name: "F", file: "a.log" }).target).toEqual({ kind: "file", file: "a.log", max_bytes: 64 * 1024 * 1024, keep: 10 });
  });
});
