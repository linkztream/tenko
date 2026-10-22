// The one read of the network boot tab that the DHCP client module (../api.ts) does not have: the
// option sets of the policies in one list, so that the tab does not ask for each policy's set.
import { fetchAll } from "../../api/paginate";
import type { OptionSet } from "../types";

/** The option sets of every policy; an owner of a path `policy:<id>`. */
export async function listPolicySets(signal?: AbortSignal): Promise<OptionSet[]> {
  return (await fetchAll<OptionSet>("/api/v1/dhcp/option-sets", { query: { level: "policy" }, signal })).items;
}
