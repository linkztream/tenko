// The SSID view of the topology page (U7, docs/topology.md section 6.2): which SSID carries
// which VLAN and how many clients sit on each. A tree of SSID, then VLAN, then clients; the
// access point and the band are columns of a client row, never levels of the tree. Per SSID
// its VLAN, the networks of that VLAN, the client count, the policy of the WLAN rules (track or
// ignore) and the count of findings. A client with a finding offers the move of its host (the
// host page, where the move flow of ADR 0027 starts) and "Keep on this WLAN".
//
// Read from the network controllers only (CONN-05); nothing here writes to a controller.
// Under Hardened with no controller allowing writes (TGL-20) the view offers no write action.
import { A } from "@solidjs/router";
import { createMemo, createSignal, For, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { errorMessage } from "../api/problem";
import { paths } from "../app/paths";
import { may, writesAll } from "../auth/gate";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { t } from "../i18n";
import type { VlanStyle } from "../ipam/vlan/palette";
import { VlanChip } from "../ipam/vlan/VlanChip";
import { getSsids, keepOnWlan, setWlanPolicy, type SsidClient, type SsidEntry, type SsidView as SsidViewData, type SsidVlan } from "./api";
import { bandWord, nodeSecondLine } from "./model";

export interface SsidViewProps {
  /** No write action at all (Hardened with TGL-20 off). */
  readOnly: boolean;
  /** The color of a VLAN, as on the map. */
  vlanStyle: (vid: number) => VlanStyle | undefined;
  /** Shows a device on the map. */
  onShowNode: (id: string) => void;
}

/** The text of an SSID's VLAN: its id and name, or "untagged". */
function vlanLabel(vlan: Pick<SsidVlan, "vid" | "name">): string {
  return vlan.vid === null || vlan.vid === undefined
    ? t("topology.ssid.untagged")
    : t("topology.ssid.vlan", { vid: vlan.vid, name: vlan.name ?? "" }).trim();
}

export function SsidView(props: SsidViewProps) {
  const live = createLiveQuery<SsidViewData>({
    topics: ["discovery", "ipam", "findings"],
    fetch: async (signal) => {
      const view = await getSsids(signal);
      return { value: view, revision: view.revision };
    },
  });
  const ssids = createMemo<SsidEntry[]>(() => live.latest()?.ssids ?? []);
  const [closed, setClosed] = createSignal<ReadonlySet<string>>(new Set());
  const toggle = (ssid: string) =>
    setClosed((prev) => {
      const next = new Set(prev);
      if (next.has(ssid)) next.delete(ssid);
      else next.add(ssid);
      return next;
    });
  const [busy, setBusy] = createSignal<string | null>(null);
  const [failure, setFailure] = createSignal<string | null>(null);

  const run = async (key: string, action: () => Promise<unknown>) => {
    setBusy(key);
    setFailure(null);
    try {
      await action();
      live.refetch();
    } catch (err) {
      setFailure(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const mayPolicy = () => !props.readOnly && writesAll();
  const mayKeep = (client: SsidClient) => !props.readOnly && client.host !== null && client.host !== undefined && may.host({ id: client.host });

  const ClientRow = (p: { client: SsidClient; ssid: string }) => {
    const second = () => nodeSecondLine({ label: p.client.label, vendor: p.client.vendor ?? null, ips: p.client.ip ? [p.client.ip] : [] });
    const key = () => `keep:${p.ssid}:${p.client.mac}`;
    return (
      <tr class="ssid-client" data-testid="ssid-client" data-mac={p.client.mac} data-findings={p.client.findings?.length ?? 0}>
        <td class="ssid-client-name">
          <Show when={p.client.node} fallback={<span>{p.client.label}</span>}>
            {(node) => (
              <button type="button" class="link" data-testid="ssid-client-show" onClick={() => props.onShowNode(node())}>
                {p.client.label}
              </button>
            )}
          </Show>
          <Show when={second()}>{(line) => <span class="ssid-second muted">{line()}</span>}</Show>
          <Show when={p.client.iot}>
            <span class="tag" data-testid="ssid-client-iot">
              {t("topology.ssid.iot_device")}
            </span>
          </Show>
        </td>
        <td class="mono">{p.client.mac}</td>
        <td class="mono">{p.client.ip ?? ""}</td>
        <td>{p.client.access_point}</td>
        <td data-testid="ssid-client-band">{bandWord(p.client.band)}</td>
        <td class="ssid-client-findings">
          <For each={p.client.findings ?? []}>
            {(kind) => (
              <span class="ssid-finding" data-testid="ssid-client-finding" data-kind={kind}>
                <Icon name="proposal" size="xs" />
                {t(kind === "wlan_class" ? "topology.ssid.finding.wlan_class" : "topology.ssid.finding.wlan_prefix")}
              </span>
            )}
          </For>
          <Show when={p.client.kept}>
            <span class="muted" data-testid="ssid-client-kept">
              <Icon name="check" size="xs" />
              {t("topology.ssid.kept")}
            </span>
          </Show>
        </td>
        <td class="ssid-client-actions">
          <Show when={(p.client.findings?.length ?? 0) > 0 && mayKeep(p.client)}>
            <A class="btn sm" data-testid="ssid-client-move" href={paths.host(p.client.label)}>
              {t("topology.ssid.move")}
            </A>
            <Show when={mayKeep(p.client)}>
              <button
                type="button"
                class="btn sm"
                data-testid="ssid-client-keep"
                disabled={busy() === key()}
                onClick={() => void run(key(), () => keepOnWlan(p.ssid, p.client.host as string))}
              >
                {t("topology.ssid.keep")}
              </button>
            </Show>
          </Show>
        </td>
      </tr>
    );
  };

  const SsidBlock = (p: { entry: SsidEntry }) => {
    const open = () => !closed().has(p.entry.ssid);
    const prefixes = () => (p.entry.vlans[0]?.prefixes ?? []).map((x) => x.cidr).join(", ") ?? "";
    const policyKey = () => `policy:${p.entry.ssid}`;
    return (
      <tbody class="ssid-block" data-testid="ssid-row" data-ssid={p.entry.ssid} data-policy={p.entry.policy}>
        <tr class="ssid-head">
          <th colspan="7" scope="rowgroup">
            <div class="ssid-head-line">
              <button
                type="button"
                class="icon-btn"
                aria-expanded={open()}
                aria-label={t(open() ? "topology.ssid.collapse" : "topology.ssid.expand", { ssid: p.entry.ssid })}
                data-testid="ssid-toggle"
                onClick={() => toggle(p.entry.ssid)}
              >
                <Icon name={open() ? "chev-d" : "chev-r"} size="sm" />
              </button>
              <Icon name="wifi" size="sm" />
              <strong class="ssid-name">{p.entry.ssid}</strong>
              <Show when={p.entry.guest}>
                <span class="tag" data-testid="ssid-guest">
                  {t("topology.ssid.guest")}
                </span>
              </Show>
              <Show
                when={p.entry.vid !== null && p.entry.vid !== undefined}
                fallback={<span class="muted">{t("topology.ssid.untagged")}</span>}
              >
                <VlanChip vid={p.entry.vid as number} name={p.entry.vlans[0]?.name ?? undefined} style={props.vlanStyle(p.entry.vid as number)} />
              </Show>
              <Show when={prefixes()}>
                <span class="mono" data-testid="ssid-prefix">
                  {prefixes()}
                </span>
              </Show>
              <span data-testid="ssid-clients">{t("topology.ssid.clients", { count: p.entry.clients })}</span>
              <Show when={p.entry.findings > 0}>
                <span class="ssid-finding" data-testid="ssid-findings">
                  <Icon name="proposal" size="xs" />
                  {t("topology.ssid.findings", { count: p.entry.findings })}
                </span>
              </Show>
              <span class="grow" />
              <Show
                when={mayPolicy()}
                fallback={
                  <span class="chip" data-testid="ssid-policy">
                    {t(p.entry.policy === "track" ? "topology.ssid.policy.track" : "topology.ssid.policy.ignore")}
                  </span>
                }
              >
                <button
                  type="button"
                  class="chip"
                  aria-pressed={p.entry.policy === "track"}
                  data-testid="ssid-policy"
                  title={t("topology.ssid.policy.hint")}
                  disabled={busy() === policyKey()}
                  onClick={() => void run(policyKey(), () => setWlanPolicy(p.entry.ssid, p.entry.policy === "track" ? "ignore" : "track"))}
                >
                  {t(p.entry.policy === "track" ? "topology.ssid.policy.track" : "topology.ssid.policy.ignore")}
                </button>
              </Show>
            </div>
          </th>
        </tr>
        <Show when={open()}>
          <For each={p.entry.vlans}>
            {(vlan) => (
              <>
                <Show when={p.entry.vlans.length > 1}>
                  <tr class="ssid-vlan" data-testid="ssid-vlan" data-vid={vlan.vid ?? ""}>
                    <td colspan="7">
                      {vlanLabel(vlan)}
                      <Show when={(vlan.prefixes?.length ?? 0) > 0}>
                        <span class="mono"> {(vlan.prefixes ?? []).map((x) => x.cidr).join(", ")}</span>
                      </Show>
                      <span class="muted"> {t("topology.ssid.clients", { count: vlan.clients.length })}</span>
                    </td>
                  </tr>
                </Show>
                <For each={vlan.clients}>{(client) => <ClientRow client={client} ssid={p.entry.ssid} />}</For>
              </>
            )}
          </For>
        </Show>
      </tbody>
    );
  };

  return (
    <div class="ssid-view" data-testid="ssid-view">
      <ErrorNotice error={live.value.error} />
      <Show when={failure()}>
        {(text) => (
          <Notice kind="bad" role="alert" testid="ssid-failure">
            {text()}
          </Notice>
        )}
      </Show>
      <Show when={props.readOnly}>
        <Notice kind="info" testid="ssid-read-only">
          {t("topology.read_only")}
        </Notice>
      </Show>
      <Show
        when={live.latest() !== undefined}
        fallback={
          <p class="muted" role="status" data-testid="ssid-loading">
            {t("topology.loading")}
          </p>
        }
      >
        <Show
          when={ssids().length > 0}
          fallback={
            <div class="empty" data-testid="ssid-empty">
              <p>{t("topology.ssid.empty")}</p>
              <A class="btn" href={paths.connectors()}>
                <Icon name="ext" />
                {t("topology.empty.link")}
              </A>
            </div>
          }
        >
          <table class="ssid-table" aria-label={t("topology.ssid.label")}>
            <thead>
              <tr>
                <th scope="col">{t("topology.ssid.col.client")}</th>
                <th scope="col">{t("topology.ssid.col.mac")}</th>
                <th scope="col">{t("topology.ssid.col.address")}</th>
                <th scope="col">{t("topology.ssid.col.access_point")}</th>
                <th scope="col">{t("topology.ssid.col.band")}</th>
                <th scope="col">{t("topology.ssid.col.findings")}</th>
                <th scope="col">
                  <span class="sr-only">{t("topology.ssid.col.actions")}</span>
                </th>
              </tr>
            </thead>
            <For each={ssids()}>{(entry) => <SsidBlock entry={entry} />}</For>
          </table>
        </Show>
      </Show>
    </div>
  );
}
