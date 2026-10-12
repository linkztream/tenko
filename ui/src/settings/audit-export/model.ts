// The audit export settings (IAM-18, TGL-21; slice-3 plan WP3.3): sinks that receive every audit
// record as syslog (UDP, TCP or TLS) or into a JSON lines file, in RFC 5424, CEF or JSON, each
// with its own cursor and delivery status, and a test record per sink.
//
// The routes belong to WP3.3, which runs in parallel; until the API document describes them,
// they are typed here as pending operations (api/pending.ts). The shapes follow section 3 of the
// plan and are reconciled with the server at merge: the type check names every entry here once
// the document has the operation.
import { t, tDynamic } from "../../i18n";

/** How a sink is reached: syslog over UDP (RFC 5426), TCP (RFC 6587), TLS (RFC 5425), or a file. */
export type SinkTransport = "udp" | "tcp" | "tls" | "file";
/** The format of the records: RFC 5424 with the record as JSON, CEF, or JSON lines. */
export type SinkFormat = "rfc5424" | "cef" | "json";

/** One sink as it is configured. */
export interface AuditSink {
  id: string;
  name: string;
  enabled: boolean;
  transport: SinkTransport;
  format: SinkFormat;
  /** The receiver of a syslog sink. */
  host?: string | null;
  port?: number | null;
  /** The certificate authority that signed the receiver's certificate (TLS); none: the system roots. */
  ca_pem?: string | null;
  /** Presents the controller's client certificate from the internal CA (TLS). */
  client_certificate?: boolean;
  /** The file of a file sink, on every controller. */
  path?: string | null;
  /** Size at which a file sink rotates, in bytes. */
  max_bytes?: number | null;
  /** How many rotated files a file sink keeps. */
  keep_files?: number | null;
}

/** How a sink delivers. */
export type SinkState = "ok" | "failing" | "idle" | "disabled";

export interface AuditSinkStatus {
  state: SinkState;
  /** The sequence number of the last record delivered. */
  cursor: number;
  /** The head of the audit chain. */
  head: number;
  last_delivery_at?: string | null;
  /** Since when deliveries fail; the alarm `audit.export.failing` follows after five minutes. */
  failing_since?: string | null;
  last_error?: string | null;
}

export interface AuditSinkView extends AuditSink {
  status: AuditSinkStatus;
}

/** `GET /settings/audit-export`. */
export interface AuditExportView {
  sinks: AuditSinkView[];
  /** TGL-21: the profile requires at least one sink (Hardened). */
  required: boolean;
  revision: number;
}

/** `PUT /settings/audit-export`. */
export interface AuditExportUpdate {
  sinks: AuditSink[];
}

/** `POST /settings/audit-export/test`: sends one test record through the sink as given. */
export interface AuditExportTest {
  sink: AuditSink;
}

export interface AuditExportTestResult {
  delivered: boolean;
  detail?: string | null;
}

// The document describes the audit export routes now (`get_audit_export`, `put_audit_export`,
// `test_audit_export`); the shapes above are the page's working model until WP3.11c moves it to
// the generated types.

export const TRANSPORTS: readonly SinkTransport[] = ["tls", "tcp", "udp", "file"];
export const FORMATS: readonly SinkFormat[] = ["rfc5424", "cef", "json"];

/** The syslog port of a transport: 6514 for TLS (RFC 5425), 514 otherwise. */
export function defaultPort(transport: SinkTransport): number {
  return transport === "tls" ? 6514 : 514;
}

/** A new sink: RFC 5424 over TLS, the default of S3-Q6. */
export function newSink(id: string): AuditSink {
  return { id, name: "", enabled: true, transport: "tls", format: "rfc5424", host: "", port: 6514, ca_pem: null, client_certificate: false };
}

/** Why a sink cannot be saved, by field; empty when it can. */
export function sinkProblems(sink: AuditSink): Partial<Record<"name" | "host" | "port" | "path", string>> {
  const out: Partial<Record<"name" | "host" | "port" | "path", string>> = {};
  if (!sink.name.trim()) out.name = t("audit_export.error.name");
  if (sink.transport === "file") {
    if (!sink.path?.trim()) out.path = t("audit_export.error.path");
  } else {
    if (!sink.host?.trim()) out.host = t("audit_export.error.host");
    const port = sink.port ?? 0;
    if (!Number.isInteger(port) || port < 1 || port > 65535) out.port = t("audit_export.error.port");
  }
  return out;
}

/** Where a sink sends to, in one line: "syslog.example.test:6514" or the file. */
export function sinkTarget(sink: AuditSink): string {
  return sink.transport === "file" ? (sink.path ?? "") : `${sink.host ?? ""}:${sink.port ?? defaultPort(sink.transport)}`;
}

/** The words of a transport, a format or a state. */
export function transportText(transport: SinkTransport): string {
  return t(`audit_export.transport.${transport}`);
}
export function formatText(format: SinkFormat): string {
  return t(`audit_export.format.${format}`);
}
export function stateText(state: SinkState): string {
  return tDynamic(`audit_export.state.${state}`) ?? state;
}

/** The records a sink still has to deliver. */
export function lag(status: AuditSinkStatus): number {
  return Math.max(0, status.head - status.cursor);
}
