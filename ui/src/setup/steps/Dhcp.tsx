// WP8.6: the DHCP step. When the `dhcp` role and the DHCP module are chosen it asks for the first
// scope: its network (one of the node's networks or a new one, which becomes an IPAM network at
// the end of setup), the pool, the router, the DNS servers (this server's address unless others
// are typed) and the lease time; and how the role listens: relay from the gateway (the reference
// topology) or direct on an interface. The scope is written through the configuration routes after
// setup; the listener goes into `tenko.toml`, whose `[dhcp]` section the result step shows. Another
// DHCP server on the same network must be switched off first: the step asks the person to confirm.
// When DHCP is not part of the installation, the step says so.
import { For, Show } from "solid-js";
import { formatList, t } from "../../i18n";
import { useWizard } from "../controller";
import { ipv4Networks, restrictedByDefault, type DhcpLeaseUnit, type DhcpListen, type DhcpStepState } from "../dhcp";
import { FOCUS } from "../gates";
import { ProblemNotice } from "../parts";

const LISTEN: readonly DhcpListen[] = ["relay", "direct"];
const UNITS: readonly DhcpLeaseUnit[] = ["hours", "days"];
/** The lease history retention each profile keeps (P3-Q13), for the privacy line. */
const HISTORY_DAYS = { home: 30, standard: 90, hardened: 90, lab: 7 } as const;

function TextField(props: { id: string; key: keyof DhcpStepState; label: string; help?: string; placeholder?: string; mono?: boolean; testid: string }) {
  const w = useWizard();
  return (
    <div class="field">
      <label for={props.id}>{props.label}</label>
      <input
        id={props.id}
        class={props.mono === false ? "input" : "input mono"}
        spellcheck={false}
        autocomplete="off"
        value={String(w.state.dhcp[props.key])}
        placeholder={props.placeholder}
        aria-describedby={props.help ? `${props.id}-help` : undefined}
        data-testid={props.testid}
        onInput={(e) => w.setDhcp(props.key, e.currentTarget.value as never)}
      />
      <Show when={props.help}>
        <span class="wz-help" id={`${props.id}-help`}>
          {props.help}
        </span>
      </Show>
    </div>
  );
}

export function Dhcp() {
  const w = useWizard();
  const dhcp = () => w.state.dhcp;
  const networks = () => ipv4Networks(w.networks());
  const step = () => w.state.step;

  return (
    <div data-testid="setup-dhcp" data-state={w.dhcpWanted() ? "wanted" : "skipped"}>
      <Show
        when={w.dhcpWanted()}
        fallback={
          <>
            <p class="wz-lede">{t("setup.dhcp.skipped")}</p>
            <ProblemNotice step={step()} />
          </>
        }
      >
        <p class="wz-lede">{t("setup.dhcp.lede")}</p>
        <ProblemNotice step={step()} />

        <div class="wz-blk">
          <h2 id="wz-dhcp-mode-title">{t("setup.dhcp.mode")}</h2>
          <div role="radiogroup" aria-labelledby="wz-dhcp-mode-title">
            <For each={["now", "later"] as const}>
              {(mode, i) => (
                <label class="wz-choice">
                  <input
                    type="radio"
                    name="wz-dhcp-mode"
                    class="rb"
                    id={i() === 0 ? FOCUS.dhcpMode : undefined}
                    checked={dhcp().mode === mode}
                    data-testid="setup-dhcp-mode"
                    data-key={mode}
                    onChange={() => w.setDhcp("mode", mode)}
                  />
                  <span>
                    <span class="t">{t(`setup.dhcp.mode.${mode}`)}</span>
                    <span class="d">{t(`setup.dhcp.mode.${mode}_description`)}</span>
                  </span>
                </label>
              )}
            </For>
          </div>
        </div>

        <Show when={dhcp().mode === "now"}>
          <div class="note warn wz-dhcp-safety" role="note" data-testid="setup-dhcp-safety">
            <span class="grow">{t("setup.dhcp.safety")}</span>
          </div>

          <div class="wz-blk">
            <h2>{t("setup.dhcp.scope")}</h2>
            <TextField id={FOCUS.dhcpNetwork} key="network" label={t("setup.dhcp.network")} help={t("setup.dhcp.network_help")} placeholder="192.0.2.0/24" testid="field-dhcp-network" />
            <Show when={networks().length > 0}>
              <div class="form-row wz-dhcp-networks" data-testid="setup-dhcp-networks">
                <span class="wz-help">{t("setup.dhcp.node_networks")}</span>
                <For each={networks()}>
                  {(n) => (
                    <button
                      type="button"
                      class="btn sm"
                      data-testid="setup-dhcp-network-choice"
                      data-key={n.prefix}
                      onClick={() => {
                        w.setDhcp("network", n.prefix);
                        w.setDhcp("address", n.address);
                        w.setDhcp("iface", n.interface);
                      }}
                    >
                      {t("setup.dhcp.use_network", { network: n.prefix, iface: n.interface })}
                    </button>
                  )}
                </For>
              </div>
            </Show>
            <div class="form-row wz-dhcp-row">
              <TextField id={FOCUS.dhcpPoolFirst} key="poolFirst" label={t("setup.dhcp.pool_first")} placeholder="192.0.2.128" testid="field-dhcp-pool-first" />
              <TextField id={FOCUS.dhcpPoolLast} key="poolLast" label={t("setup.dhcp.pool_last")} placeholder="192.0.2.254" testid="field-dhcp-pool-last" />
            </div>
            <p class="wz-help">{t("setup.dhcp.pool_help")}</p>
            <TextField id={FOCUS.dhcpRouter} key="router" label={t("setup.dhcp.router")} help={t("setup.dhcp.router_help")} placeholder="192.0.2.1" testid="field-dhcp-router" />
            <TextField
              id={FOCUS.dhcpDns}
              key="dns"
              label={t("setup.dhcp.dns")}
              help={t("setup.dhcp.dns_help")}
              placeholder={dhcp().address.trim() !== "" ? dhcp().address.trim() : t("setup.dhcp.dns_placeholder")}
              testid="field-dhcp-dns"
            />
            <div class="form-row wz-dhcp-row">
              <div class="field">
                <label for={FOCUS.dhcpLease}>{t("setup.dhcp.lease")}</label>
                <input
                  id={FOCUS.dhcpLease}
                  class="input num"
                  inputmode="numeric"
                  value={dhcp().lease}
                  data-testid="field-dhcp-lease"
                  onInput={(e) => w.setDhcp("lease", e.currentTarget.value)}
                />
              </div>
              <div class="field">
                <label for="wz-dhcp-lease-unit">{t("setup.dhcp.lease_unit")}</label>
                <select id="wz-dhcp-lease-unit" class="select" value={dhcp().leaseUnit} data-testid="field-dhcp-lease-unit" onChange={(e) => w.setDhcp("leaseUnit", e.currentTarget.value as DhcpLeaseUnit)}>
                  <For each={UNITS}>{(unit) => <option value={unit}>{t(`setup.dhcp.unit.${unit}`)}</option>}</For>
                </select>
              </div>
            </div>
            <Show when={restrictedByDefault(w.state.profile)}>
              <p class="wz-help" data-testid="setup-dhcp-hardened">
                {t("setup.dhcp.hardened")}
              </p>
            </Show>
          </div>

          <div class="wz-blk">
            <h2 id="wz-dhcp-listen-title">{t("setup.dhcp.listen")}</h2>
            <div role="radiogroup" aria-labelledby="wz-dhcp-listen-title">
              <For each={LISTEN}>
                {(mode) => (
                  <label class="wz-choice">
                    <input
                      type="radio"
                      name="wz-dhcp-listen"
                      class="rb"
                      checked={dhcp().listen === mode}
                      data-testid="setup-dhcp-listen"
                      data-key={mode}
                      onChange={() => w.setDhcp("listen", mode)}
                    />
                    <span>
                      <span class="t">{t(`setup.dhcp.listen.${mode}`)}</span>
                      <span class="d">{t(`setup.dhcp.listen.${mode}_description`)}</span>
                    </span>
                  </label>
                )}
              </For>
            </div>
            <div class="form-row wz-dhcp-row">
              <TextField
                id={FOCUS.dhcpAddress}
                key="address"
                label={t("setup.dhcp.address")}
                help={dhcp().listen === "relay" ? t("setup.dhcp.address_relay_help") : t("setup.dhcp.address_direct_help")}
                placeholder="192.0.2.10"
                testid="field-dhcp-address"
              />
              <Show when={dhcp().listen === "direct"}>
                <TextField id={FOCUS.dhcpIface} key="iface" label={t("setup.dhcp.iface")} testid="field-dhcp-iface" />
              </Show>
            </div>
          </div>

          <div class="wz-blk tight">
            <label class="wz-choice multi">
              <input
                type="checkbox"
                class="cb"
                id={FOCUS.dhcpOthersOff}
                checked={dhcp().othersOff}
                data-testid="field-dhcp-others-off"
                onChange={(e) => w.setDhcp("othersOff", e.currentTarget.checked)}
              />
              <span>
                <span class="t">{t("setup.dhcp.others_off")}</span>
                <span class="d">{t("setup.dhcp.others_off_description")}</span>
              </span>
            </label>
            <p class="wz-help" data-testid="setup-dhcp-privacy">
              {t("setup.dhcp.privacy", { days: HISTORY_DAYS[w.state.profile] })}
            </p>
            <Show when={w.dhcpPlan()}>
              {(p) => (
                <p class="wz-help" data-testid="setup-dhcp-summary">
                  {t("setup.dhcp.summary", { network: p().network, first: p().poolFirst, last: p().poolLast, router: p().router, dns: formatList(p().dns) })}
                </p>
              )}
            </Show>
          </div>
        </Show>
      </Show>
    </div>
  );
}
