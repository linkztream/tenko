// The only module of the connectors area that talks to the API (docs/plugins.md, CONN-19):
// the plugins of this node with their manifests, the connector instances, and their run and
// check. Settings travel as JSON objects validated by the host against the plugin's settings
// schema; secrets travel only as references to operator secrets, by purpose, never as values.
import { ANY_REVISION, api } from "../api/client";
import type { components } from "../api/generated/schema";
import { fetchAll } from "../api/paginate";
import type { Settings } from "./schema";

type S = components["schemas"];

export type PluginInfo = S["PluginInfo"];
export type Manifest = S["Manifest"];
export type Capability = S["Capability"];
export type SecretDecl = S["SecretDecl"];
export type NetworkTarget = S["NetworkTarget"];
export type ConnectorView = S["ConnectorView"];
export type ConnectorHealth = S["ConnectorHealth"];
export type SupervisorStatus = S["SupervisorStatus"];
export type HealthReport = S["HealthReport"];
export type RemoteHealth = S["RemoteHealth"];
export type LastRun = S["LastRun"];
export type RunAccepted = S["RunAccepted"];

/** Secret references by purpose: `{ api_key: <secret id> }`. */
export type SecretChoice = Record<string, string>;

export interface ConnectorInput {
  name: string;
  plugin: string;
  settings: Settings;
  secrets: SecretChoice;
  poll_interval_secs: number | null;
  call_timeout_secs: number | null;
  writes_enabled: boolean;
  enabled: boolean;
}

function refs(choice: SecretChoice): Record<string, { secret: string }> {
  const out: Record<string, { secret: string }> = {};
  for (const [purpose, secret] of Object.entries(choice)) if (secret) out[purpose] = { secret };
  return out;
}

export async function listPlugins(signal?: AbortSignal): Promise<PluginInfo[]> {
  const answer = await api.get("/api/v1/connectors/plugins", { signal });
  return answer.items;
}

export async function listConnectors(signal?: AbortSignal): Promise<ConnectorView[]> {
  const page = await fetchAll<ConnectorView>("/api/v1/connectors", { limit: 1000, signal });
  return page.items;
}

export function getConnector(id: string, signal?: AbortSignal): Promise<ConnectorView> {
  return api.get("/api/v1/connectors/{id}", { path: { id }, signal });
}

export function createConnector(input: ConnectorInput): Promise<ConnectorView> {
  return api.post("/api/v1/connectors", {
    body: {
      name: input.name,
      plugin: input.plugin,
      settings: input.settings as Record<string, never>,
      secrets: refs(input.secrets),
      poll_interval_secs: input.poll_interval_secs,
      call_timeout_secs: input.call_timeout_secs,
      writes_enabled: input.writes_enabled,
      enabled: input.enabled,
    },
  });
}

/** The members of a change; absent ones stay. `0` for an interval returns it to the default. */
export interface ConnectorChange {
  name?: string;
  settings?: Settings;
  secrets?: SecretChoice;
  poll_interval_secs?: number;
  call_timeout_secs?: number;
  writes_enabled?: boolean;
}

export function updateConnector(id: string, change: ConnectorChange, revision: number): Promise<ConnectorView> {
  return api.patch("/api/v1/connectors/{id}", {
    path: { id },
    body: {
      name: change.name,
      settings: change.settings as Record<string, never> | undefined,
      secrets: change.secrets ? refs(change.secrets) : undefined,
      poll_interval_secs: change.poll_interval_secs,
      call_timeout_secs: change.call_timeout_secs,
      writes_enabled: change.writes_enabled,
    },
    ifMatch: revision,
  });
}

export function deleteConnector(id: string): Promise<undefined> {
  return api.delete("/api/v1/connectors/{id}", { path: { id }, ifMatch: ANY_REVISION }) as Promise<undefined>;
}

export function setConnectorEnabled(id: string, enabled: boolean): Promise<ConnectorView> {
  return enabled
    ? api.post("/api/v1/connectors/{id}/enable", { path: { id } })
    : api.post("/api/v1/connectors/{id}/disable", { path: { id } });
}

/** Starts a run now; the answer names the job that carries it. */
export function runConnector(id: string): Promise<RunAccepted> {
  return api.post("/api/v1/connectors/{id}/run", { path: { id } });
}

/** Checks the remote system now. */
export function checkConnector(id: string): Promise<HealthReport> {
  return api.post("/api/v1/connectors/{id}/check", { path: { id } });
}
