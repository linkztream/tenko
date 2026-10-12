// The words of the scan pages: the enumerations of the model in the current language, the
// target of a scan and what a fact reports, in one line. No state here.
import type { components } from "../api/generated/schema";
import { formatList, t, tDynamic } from "../i18n";
import type { DiffItem, ScanKind, ScanState, ScanTargetKind, ScanView } from "./model";

type Observed = components["schemas"]["Observed"];

export function stateWord(state: ScanState): string {
  return t(`scans.state.${state}`);
}

export function kindWord(kind: ScanKind): string {
  return t(`scans.kind.${kind}`);
}

export function targetKindWord(kind: ScanTargetKind): string {
  return t(`scans.target.${kind}`);
}

export function changeWord(change: DiffItem["change"] | "unchanged"): string {
  return t(`scans.change.${change}`);
}

/** The word for a fact type; a type this build does not know shows as the server names it. */
export function factTypeWord(type: string): string {
  return tDynamic(`scans.fact_type.${type}`) ?? type;
}

/** The state of a probe's command; a state this build does not know shows as the server names it. */
export function partStateWord(state: string): string {
  return tDynamic(`scans.part.state.${state}`) ?? state;
}

/** The class of the glyph of a probe's command state. */
export function partGlyph(state: string): string {
  switch (state) {
    case "running":
    case "done":
      return state;
    case "failed":
    case "rejected":
    case "expired":
      return "failed";
    default:
      return "queued";
  }
}

/** A note of the server: a problem code (`scan.stopped`) in words, else the text as it is. */
export function noteText(note: string): string {
  return tDynamic(`errors.${note}`) ?? note;
}

/** What a scan covers, in words a person recognises: its networks, else the value of the target. */
export function targetText(scan: Pick<ScanView, "networks" | "target">): string {
  return scan.networks.length > 0 ? scan.networks.join(", ") : scan.target.value;
}

/** The class of the glyph of a state, among those of the job states in design.css. */
export function stateGlyph(state: ScanState): string {
  switch (state) {
    case "partial":
      return "rolledback";
    case "cancelled":
      return "queued";
    default:
      return state;
  }
}

/** The members of an observation of a type this build does not know, as `name value`. */
function otherText(o: { data?: unknown }): string {
  const data = typeof o.data === "object" && o.data !== null ? (o.data as Record<string, unknown>) : {};
  return Object.entries(data)
    .map(([k, v]) => `${k} ${Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

/** What a fact reports on its own side of a diff: the value, without the subject it belongs to. */
export function valueText(observed: Observed | null | undefined): string {
  if (!observed) return t("scans.fact.none");
  switch (observed.type) {
    case "address":
      return observed.data.mac ? t("scans.fact.address", { ip: observed.data.ip, mac: observed.data.mac }) : observed.data.ip;
    case "host": {
      const d = observed.data;
      return [d.name ?? d.external_id, d.macs?.length ? formatList(d.macs) : "", d.ips?.length ? formatList(d.ips) : "", d.os ?? ""]
        .filter(Boolean)
        .join(" · ");
    }
    case "services": {
      const ports = t("scans.fact.ports", { ports: observed.data.open_tcp.join(", ") });
      const tls = observed.data.tls_tcp;
      return Array.isArray(tls) && tls.length > 0 ? `${ports} · ${t("scans.fact.tls", { ports: tls.join(", ") })}` : ports;
    }
    case "os":
      return t("scans.fact.os", { guess: observed.data.guess, confidence: observed.data.confidence });
    case "attachment": {
      const d = observed.data;
      return t("scans.fact.attachment", { mac: d.mac, device: d.port ? `${d.device} ${d.port}` : d.device });
    }
    case "link": {
      const end = (e: { device: string; port?: string | null }) => (e.port ? `${e.device} ${e.port}` : e.device);
      return t("scans.fact.link", { a: end(observed.data.a), b: end(observed.data.b), kind: observed.data.kind });
    }
    case "name":
      return observed.data.name;
    case "vendor":
      return observed.data.vendor;
    default:
      // A type of fact that a newer server adds.
      return otherText(observed as { data?: unknown });
  }
}
