// The live strip of the lease list (WP8.6), above the filters: the scope the list is narrowed to
// (the scope filter) with a link to its page, how full that scope is (or, with no scope chosen, a
// bar for each of the first scopes and a button on each that chooses it), and the count of the
// leases granted since the page was opened. The bars are read again whenever the page reads its
// list again, which the sampler of the live view limits to one read in 200 ms.
import { A } from "@solidjs/router";
import { createMemo, createSignal, For, Show, type Accessor } from "solid-js";
import { t } from "../../i18n";
import type { Scope } from "../api";
import { dhcpPaths } from "../paths";
import { UtilizationBar } from "../UtilizationBar";
import { NewCounter } from "./NewCounter";
import { barPlan } from "./overview";

/** How full the chosen scope is, with the figures behind it. */
function ChosenBar(props: { prefix: string; version: Accessor<number> }) {
  const [percent, setPercent] = createSignal<number | undefined>();
  return (
    <span class="dhcp-live-bar" data-testid="leases-utilization" data-value={percent() === undefined ? undefined : String(percent())}>
      <UtilizationBar prefix={props.prefix} revision={props.version()} detail onRead={setPercent} />
    </span>
  );
}

/** A bar for each of the first scopes, the fullest first once read; each chooses its scope. */
function ScopeBars(props: { scopes: readonly Scope[]; version: Accessor<number>; onPick: (prefix: string) => void }) {
  const [read, setRead] = createSignal<Readonly<Record<string, number>>>({});
  const note = (prefix: string, percent: number) => setRead((before) => (before[prefix] === percent ? before : { ...before, [prefix]: percent }));
  const plan = createMemo(() => barPlan(props.scopes, read()));
  return (
    <Show when={props.scopes.length > 0}>
      <span class="dhcp-scope-bars" role="group" aria-label={t("dhcp.live.bars_label")} data-testid="leases-scope-bars">
        <For each={plan().shown}>
          {(scope) => (
            <button
              type="button"
              class="btn sm dhcp-scope-bar"
              title={t("dhcp.live.scope_pick", { network: scope.cidr })}
              data-testid="leases-scope-bar"
              data-key={scope.cidr}
              onClick={() => props.onPick(scope.prefix)}
            >
              <span class="mono">{scope.cidr}</span>
              <UtilizationBar prefix={scope.prefix} revision={props.version()} onRead={(percent) => note(scope.prefix, percent)} />
            </button>
          )}
        </For>
        <Show when={plan().more > 0}>
          <A class="dhcp-fact" href={dhcpPaths.scopes()} data-testid="leases-scope-more" data-count={String(plan().more)}>
            {t("dhcp.live.scope_more", { count: plan().more })}
          </A>
        </Show>
      </span>
    </Show>
  );
}

export function LiveStrip(props: {
  /** The prefix of the scope filter, or the empty string. */
  scope: string;
  scopes: readonly Scope[];
  /** The network of a scope; its prefix when the scope is not known. */
  networkOf: (prefix: string) => string;
  /** Changes whenever the page reads its list again. */
  version: Accessor<number>;
  live: Accessor<boolean>;
  /** When the counting of the new leases started: RFC 3339. */
  since: string;
  onReset: () => void;
  onPick: (prefix: string) => void;
}) {
  return (
    <div class="dhcp-strip dhcp-live-strip" role="group" aria-label={t("dhcp.live.strip_label")} data-testid="leases-live-strip" data-scope={props.scope}>
      <span class="dhcp-fact dhcp-live-scope">
        <span class="muted">{t("dhcp.lfilter.scope")}</span>{" "}
        <Show when={props.scope !== ""} fallback={<b data-testid="leases-scope-name">{t("dhcp.lfilter.scope_any")}</b>}>
          <b class="mono" data-testid="leases-scope-name">
            {props.networkOf(props.scope)}
          </b>{" "}
          <A href={dhcpPaths.scope(props.scope)} data-testid="leases-scope-link">
            {t("dhcp.live.scope_open")}
          </A>
        </Show>
      </span>
      <Show when={props.scope !== ""} fallback={<ScopeBars scopes={props.scopes} version={props.version} onPick={props.onPick} />}>
        <Show when={props.scope} keyed>
          {(prefix) => <ChosenBar prefix={prefix} version={props.version} />}
        </Show>
      </Show>
      <NewCounter since={props.since} scope={props.scope} version={props.version} live={props.live} onReset={props.onReset} />
    </div>
  );
}
