// The API calls of the VLAN provision dialog and of the prefix list of a VLAN (docs/topology.md,
// section 8): the only module of these pieces that calls the client. A preview is a dry run;
// the submit sends the same request without it and the key of this one confirmation, so a retry
// answers the first result (`replayed`).
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { fetchAll } from "../../api/paginate";
import type { Prefix, Site, Vrf } from "../../api/types";

export { newIdempotencyKey } from "../../api/client";

type S = components["schemas"];

export type VlanProvisionRequest = S["VlanProvisionRequest"];
export type VlanProvisionPreview = S["VlanProvisionPreview"];
export type VlanProvisionSubmitted = S["VlanProvisionSubmitted"];
export type VlanStepPreview = S["VlanStepPreview"];
export type VlanTarget = S["VlanTarget"];
export type PrefixTarget = S["PrefixTarget"];
export type ControllerPreview = S["ControllerPreview"];
export type ControllerMode = S["ControllerMode"];
export type ControllerInfo = S["ControllerInfo"];
export type DiffEntry = S["DiffEntry"];
export type NewVlan = S["NewVlan"];
export type NewVlanPrefix = S["NewVlanPrefix"];

/** The preview of a provision (`dry_run=true`): nothing is written. */
export function previewProvision(request: VlanProvisionRequest, signal?: AbortSignal): Promise<VlanProvisionPreview> {
  return api.post("/api/v1/vlans/provision", { query: { dry_run: true }, body: request, signal }) as Promise<VlanProvisionPreview>;
}

/** Starts the job of a provision (202). Pass the same key to retry this one confirmation. */
export function submitProvision(request: VlanProvisionRequest, idempotencyKey: string): Promise<VlanProvisionSubmitted> {
  return api.post("/api/v1/vlans/provision", { body: request, idempotencyKey }) as Promise<VlanProvisionSubmitted>;
}

/** The live prefixes linked to a VLAN, by VRF and network. */
export async function listVlanPrefixes(vlan: string, signal?: AbortSignal): Promise<Prefix[]> {
  return (await fetchAll<Prefix>("/api/v1/vlans/{id}/prefixes", { path: { id: vlan }, signal })).items;
}

/** The sites for the site choice of a new VLAN. */
export async function listSites(): Promise<Site[]> {
  return (await fetchAll<Site>("/api/v1/sites")).items;
}

/** The VRFs for the VRF choice of the network. */
export async function listVrfs(): Promise<Vrf[]> {
  return (await fetchAll<Vrf>("/api/v1/vrfs")).items;
}
