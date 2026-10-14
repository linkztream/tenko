// The guardrails (WP3.11d, WP3.12a; docs/connectors-unifi.md, section 6): the wire shapes are the
// generated ones, and this file holds the limits of the server that are checked before anything is
// sent, the draft of a path in the add dialog and the words for one protected path.
import type { components } from "../../api/generated/schema";
import { ApiError, errorMessage } from "../../api/problem";
import { t } from "../../i18n";

type S = components["schemas"];

export type Guardrails = S["Guardrails"];
export type ProtectedPath = S["ProtectedPath"];
export type PathKind = ProtectedPath["type"];

export const KINDS: readonly PathKind[] = ["port", "network", "vlan", "client"];

export const MIN_PARALLEL = 1;
export const MAX_PARALLEL = 64;
export const DEFAULT_PARALLEL = 10;
export const MAX_PATHS = 256;
export const MAX_REF = 128;
export const MIN_VID = 1;
export const MAX_VID = 4094;

/** `00-00-5E-00-53-01`, `0000.5e00.5301` or `00005e005301` as `00:00:5e:00:53:01`; null when not a MAC. */
export function normalizeMac(text: string): string | null {
  const hex = text.trim().replace(/[-:.\s]/g, "").toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(hex)) return null;
  return hex.match(/.{2}/g)!.join(":");
}

/** Whether a text is a whole number in `min..=max`; the number or null. */
export function wholeNumber(text: string, min: number, max = Number.MAX_SAFE_INTEGER): number | null {
  const trimmed = text.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const value = Number(trimmed);
  return value >= min && value <= max ? value : null;
}

/** `max_parallel` as typed: the number, or null when it is not a whole number from 1 to 64. */
export function parallelOf(text: string): number | null {
  return wholeNumber(text, MIN_PARALLEL, MAX_PARALLEL);
}

/** A key that tells two paths apart: the server refuses duplicates. */
export function pathKey(path: ProtectedPath): string {
  switch (path.type) {
    case "port":
      return `port:${path.device}/${path.port}`;
    case "network":
      return `network:${path.network}`;
    case "vlan":
      return `vlan:${path.vid}`;
    case "client":
      return `client:${path.mac}`;
  }
}

/** The path in words, for a row and for the label of its remove button. */
export function pathText(path: ProtectedPath): string {
  switch (path.type) {
    case "port":
      return t("guardrails.path.port", { device: path.device, port: String(path.port) });
    case "network":
      return path.network;
    case "vlan":
      return t("guardrails.path.vlan", { vid: String(path.vid) });
    case "client":
      return path.mac;
  }
}

export function kindText(kind: PathKind): string {
  switch (kind) {
    case "port":
      return t("guardrails.kind.port");
    case "network":
      return t("guardrails.kind.network");
    case "vlan":
      return t("guardrails.kind.vlan");
    case "client":
      return t("guardrails.kind.client");
  }
}

/** The fields of the add dialog as typed. */
export interface PathDraft {
  kind: PathKind;
  device: string;
  port: string;
  network: string;
  vid: string;
  mac: string;
}

export const EMPTY_DRAFT: PathDraft = { kind: "vlan", device: "", port: "", network: "", vid: "", mac: "" };

export type PathErrors = Partial<Record<"device" | "port" | "network" | "vid" | "mac", string>>;

function referenceError(text: string): string | undefined {
  const length = [...text.trim()].length;
  return length >= 1 && length <= MAX_REF ? undefined : t("guardrails.error.reference", { max: MAX_REF });
}

/** The path a draft stands for, or the problems of its fields. */
export function pathOfDraft(draft: PathDraft): { path: ProtectedPath } | { errors: PathErrors } {
  switch (draft.kind) {
    case "port": {
      const port = wholeNumber(draft.port, 0, 2_147_483_647);
      const errors: PathErrors = {};
      const device = referenceError(draft.device);
      if (device) errors.device = device;
      if (port === null) errors.port = t("guardrails.error.port");
      if (Object.keys(errors).length > 0 || port === null) return { errors };
      return { path: { type: "port", device: draft.device.trim(), port } };
    }
    case "network": {
      const network = referenceError(draft.network);
      return network ? { errors: { network } } : { path: { type: "network", network: draft.network.trim() } };
    }
    case "vlan": {
      const vid = wholeNumber(draft.vid, MIN_VID, MAX_VID);
      return vid === null ? { errors: { vid: t("guardrails.error.vid", { min: MIN_VID, max: MAX_VID }) } } : { path: { type: "vlan", vid } };
    }
    case "client": {
      const mac = normalizeMac(draft.mac);
      return mac === null ? { errors: { mac: t("guardrails.error.mac") } } : { path: { type: "client", mac } };
    }
  }
}

/**
 * The words of a refused save. The key for the code `connect.guardrails.invalid` would sit in the
 * connectors pack, which this page does not load, so the text lives in this page's own key.
 */
export function saveErrorText(err: unknown): string {
  if (err instanceof ApiError && err.code === "connect.guardrails.invalid") {
    return t("guardrails.error.invalid", { field: err.params["field"] ?? "" });
  }
  return errorMessage(err);
}
