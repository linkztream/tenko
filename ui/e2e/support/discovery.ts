// Arrangement for the discovery and connector scenarios over the public API: an instance of
// the bundled sample plugin (docs/plugins.md), which reports documentation data and contacts
// nothing, run once so its observations reach the reconciler, and short reads of proposals
// and observations. The sample's host `n` (from 0) is `host-<n>.example.test` with the MAC
// address 00:00:5e:00:53:<n> and the addresses 192.0.2.<n + 10> and 2001:db8::<n + 16>
// (hexadecimal); every host carries the tag of the `site` setting (default `lab`).
//
// The reconciler runs 2 seconds after an ingest that wrote something, so proposals follow a
// run without a request; `reconcile(api)` runs it at once where a test wants no delay.

import { expect } from "@playwright/test";
import type { Api, Schemas } from "./api";

export type ConnectorView = Schemas["ConnectorView"];
export type Proposal = Schemas["IntentProposal"];
export type ObservedFact = Schemas["ObservedFact"];

/** The sample host `index` as the plugin reports it. */
export function sampleHost(index: number): { name: string; mac: string; ipv4: string; ipv6: string } {
  const low = index % 200;
  return {
    name: `host-${index}.example.test`,
    mac: `00:00:5e:00:53:${low.toString(16).padStart(2, "0")}`,
    ipv4: `192.0.2.${low + 10}`,
    ipv6: `2001:db8::${(low + 0x10).toString(16)}`,
  };
}

/** Creates an instance of the sample plugin and waits until its process runs. */
export async function createSampleConnector(
  api: Api,
  name = "Lab sample",
  settings: Record<string, unknown> = { hosts: 3 },
): Promise<ConnectorView> {
  const created = await api.post<ConnectorView>("/connectors", { plugin: "sample", name, settings });
  await waitForConnectorProcess(api, created.id, "running");
  return api.get<ConnectorView>(`/connectors/${created.id}`);
}

/** Waits until the plugin process of an instance is in `state` (`running`, `stopped`, ...). */
export async function waitForConnectorProcess(api: Api, id: string, state: string): Promise<void> {
  await expect
    .poll(async () => (await api.get<ConnectorView>(`/connectors/${id}`)).health.process.state, {
      message: `the plugin process of connector ${id} to be ${state}`,
      timeout: 60_000,
    })
    .toBe(state);
}

/** Runs an instance now and waits for its run job; returns the final job. */
export async function runConnector(api: Api, id: string): Promise<Schemas["JobDetail"]> {
  const accepted = await api.post<Schemas["RunAccepted"]>(`/connectors/${id}/run`, {});
  const detail = await api.waitForJob(accepted.job);
  expect(detail.job.state, JSON.stringify(detail.job)).toBe("succeeded");
  return detail;
}

/** Runs the reconciler once, now. */
export async function reconcile(api: Api): Promise<Schemas["ReconcileReport"]> {
  return api.post<Schemas["ReconcileReport"]>("/proposals/reconcile", {});
}

/** The proposals that match `query` (`state`, `kind`, `subject`, `prefix`, ...). */
export async function proposals(api: Api, query: Record<string, string> = {}): Promise<Proposal[]> {
  return (await api.get<Schemas["Page_IntentProposal"]>("/proposals", { limit: 1000, ...query })).items;
}

/** Waits until `count` proposals match `query` and returns them. */
export async function waitForProposals(api: Api, query: Record<string, string>, count: number): Promise<Proposal[]> {
  let found: Proposal[] = [];
  await expect
    .poll(
      async () => {
        found = await proposals(api, query);
        return found.length;
      },
      { message: `${count} proposals for ${JSON.stringify(query)}`, timeout: 60_000 },
    )
    .toBe(count);
  return found;
}

/** The facts that match `query` (`source`, `type`, `mac`, `ip`, `current`, ...). */
export async function observations(api: Api, query: Record<string, string> = {}): Promise<ObservedFact[]> {
  return (await api.get<Schemas["Page_ObservedFact"]>("/observations", { limit: 1000, ...query })).items;
}
