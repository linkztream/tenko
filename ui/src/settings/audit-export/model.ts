// The audit export settings (IAM-18, TGL-21; docs/audit-export.md): sinks that receive every audit
// record as syslog (UDP, TCP or TLS) or into a file, in RFC 5424, CEF or JSON, each with its own
// cursor and delivery status, and a test message per sink.
//
// The wire shapes are the generated ones of the OpenAPI document (`get_audit_export`,
// `put_audit_export`, `test_audit_export`). This module holds the rules the page follows: the
// words of the states, the form of a sink and its conversion to and from `SinkSpec`, and the
// checks that run before the server's.
import type { components } from "../../api/generated/schema";
import { ApiError, fieldErrorMessage } from "../../api/problem";
import { t, tDynamic } from "../../i18n";

type S = components["schemas"];

export type AuditExportView = S["AuditExportView"];
export type AuditExportUpdate = S["AuditExportUpdate"];
export type AuditExportTest = S["AuditExportTest"];
export type AuditExportTestResult = S["AuditExportTestResult"];
export type Sink = S["Sink"];
export type SinkSpec = S["SinkSpec"];
export type SinkView = S["SinkView"];
export type SinkStatus = S["SinkStatus"];
export type SinkState = S["SinkState"];
export type SinkTarget = S["SinkTarget"];
export type SyslogTarget = S["SyslogTarget"];
export type SyslogTransport = S["SyslogTransport"];
export type FileTarget = S["FileTarget"];
export type TlsOptions = S["TlsOptions"];
export type ExportFormat = S["ExportFormat"];
export type Facility = S["Facility"];
export type ExportPolicy = S["ExportPolicy"];
export type ExportWarning = S["ExportWarning"];
export type SinkFailure = S["SinkFailure"];
export type CheckpointMark = S["CheckpointMark"];
export type ChainHead = S["ChainHead"];

/** What the first choice of the editor stands for: a syslog transport, or the file. */
export type SinkChoice = SyslogTransport | "file";

export const CHOICES: readonly SinkChoice[] = ["tls", "tcp", "udp", "file"];
export const FORMATS: readonly ExportFormat[] = ["rfc5424", "cef", "json"];
/** The six states, from "not yet running" to the alarm. */
export const STATES: readonly SinkState[] = ["disabled", "pending", "ok", "behind", "failing", "alarm"];
/** The syslog facilities (RFC 5424 section 6.2.1) in the order of their codes. */
export const FACILITIES: readonly Facility[] = [
  "user",
  "daemon",
  "auth",
  "authpriv",
  "log_audit",
  "local0",
  "local1",
  "local2",
  "local3",
  "local4",
  "local5",
  "local6",
  "local7",
];

const MIB = 1024 * 1024;
/** The server's defaults and limits (docs/audit-export.md, section 2 and 10). */
export const DEFAULT_FACILITY: Facility = "authpriv";
export const DEFAULT_MAX_BYTES = 64 * MIB;
export const MIN_MAX_BYTES = 64 * 1024;
export const MAX_MAX_BYTES = 2 ** 40;
export const DEFAULT_KEEP = 10;
export const MAX_KEEP = 1000;
export const DEFAULT_ALERT_AFTER_SECS = 300;
export const ALERT_AFTER_RANGE = { min: 10, max: 86_400 } as const;
export const MAX_SINKS = 8;

/** The syslog port of a transport: 6514 for TLS (RFC 5425), 514 otherwise. */
export function defaultPort(transport: SyslogTransport): number {
  return transport === "tls" ? 6514 : 514;
}

// ---------------------------------------------------------------------------------
// The form of a sink

/** A sink as the editor holds it: text fields stay text until they are checked. */
export interface SinkForm {
  /** The id of a stored sink; null for a new one. */
  id: string | null;
  name: string;
  enabled: boolean;
  format: ExportFormat;
  choice: SinkChoice;
  host: string;
  /** Empty: the default port of the transport. */
  port: string;
  facility: Facility;
  ca_pem: string;
  server_name: string;
  client_cert_pem: string;
  /** The id of the operator secret that holds the client key. */
  client_key: string;
  file: string;
  /** In MiB, decimals allowed (the minimum is 64 KiB). */
  max_mib: string;
  keep: string;
}

/** A new sink: RFC 5424 over TLS, the default of S3-Q6. */
export function newForm(): SinkForm {
  return {
    id: null,
    name: "",
    enabled: true,
    format: "rfc5424",
    choice: "tls",
    host: "",
    port: String(defaultPort("tls")),
    facility: DEFAULT_FACILITY,
    ca_pem: "",
    server_name: "",
    client_cert_pem: "",
    client_key: "",
    file: "",
    max_mib: String(DEFAULT_MAX_BYTES / MIB),
    keep: String(DEFAULT_KEEP),
  };
}

/** The form of a stored sink. */
export function formOf(sink: Sink): SinkForm {
  const form: SinkForm = { ...newForm(), id: sink.id, name: sink.name, enabled: sink.enabled, format: sink.format };
  const target = sink.target;
  if (target.kind === "file") {
    return {
      ...form,
      choice: "file",
      port: "",
      file: target.file,
      max_mib: String((target.max_bytes ?? DEFAULT_MAX_BYTES) / MIB),
      keep: String(target.keep ?? DEFAULT_KEEP),
    };
  }
  const transport = target.transport ?? "tls";
  return {
    ...form,
    choice: transport,
    host: target.host,
    port: target.port == null ? "" : String(target.port),
    facility: target.facility ?? DEFAULT_FACILITY,
    ca_pem: target.tls?.ca_pem ?? "",
    server_name: target.tls?.server_name ?? "",
    client_cert_pem: target.tls?.client_cert_pem ?? "",
    client_key: target.tls?.client_key ?? "",
  };
}

/** Moves the form to another transport (or to the file) and fixes what depended on the old one. */
export function withChoice(form: SinkForm, choice: SinkChoice): SinkForm {
  const wasFile = form.choice === "file";
  const isFile = choice === "file";
  let port = form.port;
  if (isFile) port = "";
  else if (wasFile || port === "" || port === String(defaultPort(form.choice as SyslogTransport))) port = String(defaultPort(choice));
  return {
    ...form,
    choice,
    port,
    // A file is JSON lines by default; coming back to syslog restores RFC 5424.
    format: wasFile !== isFile ? (isFile ? "json" : "rfc5424") : form.format,
  };
}

function textOrNull(text: string): string | null {
  const trimmed = text.trim();
  return trimmed === "" ? null : text.trim();
}

/** Bytes of the size field; NaN when it is not a number. */
export function maxBytesOf(form: SinkForm): number {
  return form.max_mib.trim() === "" ? DEFAULT_MAX_BYTES : Math.round(Number(form.max_mib) * MIB);
}

/** The `SinkSpec` a valid form stands for (the update and the test take it). */
export function specOf(form: SinkForm): SinkSpec {
  const common = { name: form.name.trim(), enabled: form.enabled, format: form.format, ...(form.id ? { id: form.id } : {}) };
  if (form.choice === "file") {
    return {
      ...common,
      target: {
        kind: "file",
        file: form.file.trim(),
        max_bytes: maxBytesOf(form),
        keep: form.keep.trim() === "" ? DEFAULT_KEEP : Number(form.keep),
      },
    };
  }
  const tls: TlsOptions =
    form.choice === "tls"
      ? {
          ca_pem: textOrNull(form.ca_pem),
          server_name: textOrNull(form.server_name),
          client_cert_pem: textOrNull(form.client_cert_pem),
          client_key: textOrNull(form.client_key),
        }
      : {};
  return {
    ...common,
    target: {
      kind: "syslog",
      transport: form.choice,
      host: form.host.trim(),
      port: form.port.trim() === "" ? null : Number(form.port),
      facility: form.facility,
      ...(form.choice === "tls" ? { tls } : {}),
    },
  };
}

/** The spec of a stored sink, as the update sends it back. */
export function specOfSink(sink: Sink): SinkSpec {
  return specOf(formOf(sink));
}

/** Whether the form still says what the stored sink says (a test of the stored sink then needs no spec). */
export function sameAsStored(form: SinkForm, sink: Sink | undefined): boolean {
  return !!sink && JSON.stringify(specOf(form)) === JSON.stringify(specOfSink(sink));
}

export type FormField =
  | "name"
  | "host"
  | "port"
  | "server_name"
  | "ca_pem"
  | "client_cert_pem"
  | "client_key"
  | "file"
  | "max_mib"
  | "keep";
export type FormProblems = Partial<Record<FormField, string>>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FILE_NAME = /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/;

/** Why a sink cannot be saved, by field; empty when it can. The server checks again. */
export function formProblems(form: SinkForm): FormProblems {
  const out: FormProblems = {};
  if (!form.name.trim()) out.name = t("audit_export.error.name");
  if (form.choice === "file") {
    if (!FILE_NAME.test(form.file.trim())) out.file = t("audit_export.error.file");
    const bytes = maxBytesOf(form);
    if (!Number.isFinite(bytes) || bytes < MIN_MAX_BYTES || bytes > MAX_MAX_BYTES) out.max_mib = t("audit_export.error.max_mib");
    const keep = form.keep.trim() === "" ? DEFAULT_KEEP : Number(form.keep);
    if (!Number.isInteger(keep) || keep < 0 || keep > MAX_KEEP) out.keep = t("audit_export.error.keep");
    return out;
  }
  if (!form.host.trim()) out.host = t("audit_export.error.host");
  if (form.port.trim() !== "") {
    const port = Number(form.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) out.port = t("audit_export.error.port");
  }
  if (form.choice === "tls") {
    const cert = form.client_cert_pem.trim() !== "";
    const key = form.client_key.trim() !== "";
    if (cert !== key || (key && !UUID.test(form.client_key.trim()))) out.client_key = t("audit_export.error.client_key");
  }
  return out;
}

/** The form field a server field path (`sinks[0].target.host`, `spec.name`) belongs to. */
const SERVER_FIELDS: Record<string, FormField> = {
  name: "name",
  "target.host": "host",
  "target.port": "port",
  "target.tls.server_name": "server_name",
  "target.tls.ca_pem": "ca_pem",
  "target.tls.client_cert_pem": "client_cert_pem",
  "target.tls.client_key": "client_key",
  "target.file": "file",
  "target.max_bytes": "max_mib",
  "target.keep": "keep",
};

/** The problems the server reported for the fields of the form, in the words of the UI. */
export function serverProblems(error: unknown): FormProblems {
  const out: FormProblems = {};
  if (!(error instanceof ApiError)) return out;
  for (const e of error.fieldErrors) {
    const field = SERVER_FIELDS[e.field.replace(/^(?:sinks\[\d+\]|spec)\./, "")];
    if (field && !out[field]) out[field] = fieldErrorMessage(e);
  }
  return out;
}

// ---------------------------------------------------------------------------------
// Words and figures

/** Where a sink sends to, in one line: "syslog.example.test:6514" or the file name. */
export function sinkTarget(sink: Sink): string {
  const target = sink.target;
  if (target.kind === "file") return target.file;
  const transport = target.transport ?? "tls";
  return `${target.host}:${target.port ?? defaultPort(transport)}`;
}

/** The choice a stored sink stands for. */
export function choiceOf(sink: Sink): SinkChoice {
  return sink.target.kind === "file" ? "file" : (sink.target.transport ?? "tls");
}

export function choiceText(choice: SinkChoice): string {
  return t(`audit_export.transport.${choice}`);
}
export function formatText(format: ExportFormat): string {
  return t(`audit_export.format.${format}`);
}
export function stateText(state: SinkState): string {
  return tDynamic(`audit_export.state.${state}`) ?? state;
}

/** The class of the chip of a state (design.css `.tag`): never color alone, the chip carries the word. */
export function stateTag(state: SinkState): string {
  switch (state) {
    case "ok":
      return "ok";
    case "behind":
      return "discrepancy";
    case "failing":
    case "alarm":
      return "conflict";
    case "pending":
      return "accent";
    default:
      return "";
  }
}

/** A failure in one line: the stable code and the English detail the server gives. */
export function failureText(failure: SinkFailure): string {
  return failure.detail ? `${failure.code}: ${failure.detail}` : failure.code;
}

/** The records a sink still has to deliver. */
export function lag(status: SinkStatus): number {
  return Math.max(0, status.lag);
}

/** The translated text of a status warning; the server's English detail when the code is new. */
export function warningText(warning: ExportWarning): string {
  const params: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(warning.params ?? {})) params[key] = /^\d+$/.test(value) ? Number(value) : value;
  return tDynamic(`audit_export.${warning.code.replace(/^audit\.export\./, "warning.")}`, params) ?? warning.detail;
}

/** The value of TGL-21 in words. */
export function policyText(policy: ExportPolicy): string {
  return tDynamic(`toggles.audit_export.${policy.audit_export}`) ?? policy.audit_export;
}
