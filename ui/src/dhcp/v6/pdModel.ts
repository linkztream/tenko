// The delegation pools of a DHCPv6 scope (WP9.2, docs/dhcp.md section 19.10): a pool is an IPAM
// range of the role `dhcp_pd_pool` with the length of the prefixes it hands to routers. The scope's
// pool list (`GET /dhcp/pools`) carries them with the address pools; a new one is made through
// IPAM (`POST /prefixes/{id}/ranges`), because the range is IPAM's. The checks here are the form's
// own, the server checks again and answers `ipam.validation` with the field.
import { api } from "../../api/client";
import type { Range, WriteResponse } from "../../api/types";
import { t } from "../../i18n";
import { checkDelegatedLen, onBoundary } from "../../ipam/prefix/delegation";
import { addressIn } from "../../ipam/prefix/inputs";
import { formatIp, parseCidr, parseIp } from "../../ipam/ip";
import type { Pool } from "../types";

/** Whether a pool of the scope list is a delegation pool. */
export function isPdPool(pool: Pick<Pool, "role">): boolean {
  return pool.role === "dhcp_pd_pool";
}

/** What the add dialog collects. */
export interface PdDraft {
  first: string;
  last: string;
  /** The delegated length as typed. */
  len: string;
}

/** What is sent to make the pool. */
export interface PdBody {
  first: string;
  last: string;
  delegated_len: number;
}

export type PdProblems = Partial<Record<"first" | "last" | "delegated_len", string>>;

/**
 * Checks a draft against the network of the scope: both addresses inside it, in order, the length
 * longer than the network's and at most 64, and the addresses on boundaries of that length.
 */
export function checkPdDraft(draft: PdDraft, networkCidr: string): { ok: true; body: PdBody } | { ok: false; problems: PdProblems } {
  const network = parseCidr(networkCidr);
  const problems: PdProblems = {};
  const addressProblem = (text: string): string | undefined => {
    if (text.trim() === "") return t("dhcp.pd.field.ip_required");
    const where = network ? addressIn(network, text) : parseIp(text) ? "ok" : "invalid";
    if (where === "invalid") return t("dhcp.pd.field.ip_invalid");
    if (where === "outside") return t("errors.ipam.range.outside_prefix", { cidr: networkCidr });
    return undefined;
  };
  const first = addressProblem(draft.first);
  const last = addressProblem(draft.last);
  if (first) problems.first = first;
  if (last) problems.last = last;
  const a = parseIp(draft.first);
  const b = parseIp(draft.last);
  if (!last && a && b && a.value > b.value) problems.last = t("dhcp.pd.field.last_before_first");

  const len = checkDelegatedLen(draft.len, network?.length ?? null);
  if (!len.ok) {
    problems.delegated_len =
      len.reason === "required"
        ? t("dhcp.pd.field.delegated_required")
        : len.reason === "number"
          ? t("dhcp.pd.field.delegated_number")
          : t("dhcp.pd.field.delegated_range", { length: network?.length ?? 0 });
  } else {
    if (!first && !onBoundary(draft.first, len.len, "first")) problems.first = t("dhcp.pd.field.delegated_first", { len: len.len });
    if (!problems.last && !last && !onBoundary(draft.last, len.len, "last")) problems.last = t("dhcp.pd.field.delegated_last", { len: len.len });
  }
  if (Object.keys(problems).length > 0 || !a || !b || !len.ok) return { ok: false, problems };
  return { ok: true, body: { first: formatIp(a), last: formatIp(b), delegated_len: len.len } };
}

/** Makes a delegation pool, an IPAM range of the network of the scope. */
export async function createPdPool(prefix: string, body: PdBody): Promise<Range> {
  const done = (await api.post("/api/v1/prefixes/{id}/ranges", {
    path: { id: prefix },
    body: { ...body, role: "dhcp_pd_pool" },
  })) as WriteResponse<Range>;
  if (!done.item) throw new Error("the server answered no range");
  return done.item;
}
