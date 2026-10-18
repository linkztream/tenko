// The pure helpers of the block lists page: the form of a list as typed, its local checks
// (the server checks again, `dns.list.invalid` with `field`), and the readable forms of a
// list's source and action. No translated text here.
import { parseIp } from "../../ipam/ip";
import type { BlockAction, ListCreate, ListFormat } from "./api";

export const FORMATS: readonly ListFormat[] = ["hosts", "domains"];
export const ACTIONS: readonly BlockAction["kind"][] = ["nxdomain", "nodata", "redirect"];

/** How often a URL list is fetched when the person does not say (hours), and the bounds. */
export const DEFAULT_INTERVAL = 24;
export const MIN_INTERVAL = 1;
export const MAX_INTERVAL = 168;

export interface ListDraft {
  name: string;
  source: "url" | "upload";
  url: string;
  format: ListFormat;
  interval: string;
  action: BlockAction["kind"];
  redirect: string;
  enabled: boolean;
  description: string;
}

export type ListProblem = "name" | "url" | "interval" | "redirect";

export type CheckedList = { ok: true; body: ListCreate } | { ok: false; problems: ListProblem[] };

const NAME = /^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,63}$/u;

/** The local checks of a list; the body to send when they pass. */
export function checkList(draft: ListDraft): CheckedList {
  const problems: ListProblem[] = [];
  const name = draft.name.trim();
  if (!NAME.test(name) || name.length > 64) problems.push("name");
  const url = draft.url.trim();
  if (draft.source === "url" && !validUrl(url)) problems.push("url");
  const interval = Number(draft.interval.trim());
  const intervalOk = /^\d+$/.test(draft.interval.trim()) && interval >= MIN_INTERVAL && interval <= MAX_INTERVAL;
  if (draft.source === "url" && !intervalOk) problems.push("interval");
  const redirect = draft.redirect.trim();
  if (draft.action === "redirect" && !parseIp(redirect)) problems.push("redirect");
  if (problems.length > 0) return { ok: false, problems };
  const action: BlockAction = draft.action === "redirect" ? { kind: "redirect", address: redirect.toLowerCase() } : { kind: draft.action };
  return {
    ok: true,
    body: {
      name,
      source: draft.source === "url" ? { kind: "url", url } : { kind: "upload" },
      format: draft.format,
      action,
      enabled: draft.enabled,
      interval_hours: draft.source === "url" ? interval : null,
      description: draft.description.trim() || null,
    },
  };
}

/** An `https://` or `http://` URL with a host. */
export function validUrl(text: string): boolean {
  if (!/^https?:\/\/[^/\s]/i.test(text)) return false;
  try {
    return new URL(text).hostname !== "";
  } catch {
    return false;
  }
}

/** The draft of a new list, or of an existing one for its edit form. */
export function draftOf(list?: {
  name: string;
  source: { kind: "url"; url: string } | { kind: "upload" };
  format: ListFormat;
  interval_hours?: number;
  action: BlockAction;
  enabled?: boolean;
  description?: string | null;
}): ListDraft {
  return {
    name: list?.name ?? "",
    source: list?.source.kind ?? "url",
    url: list?.source.kind === "url" ? list.source.url : "",
    format: list?.format ?? "domains",
    interval: String(list?.interval_hours || DEFAULT_INTERVAL),
    action: list?.action.kind ?? "nxdomain",
    redirect: list?.action.kind === "redirect" ? list.action.address : "",
    enabled: list?.enabled ?? true,
    description: list?.description ?? "",
  };
}

/** The address a redirect answers, else nothing. */
export function redirectOf(action: BlockAction): string | undefined {
  return action.kind === "redirect" ? action.address : undefined;
}
