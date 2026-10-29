// The four truths of a row of the reconciliation view (intent, the lease, DNS, the scans), in two
// sizes: one line for a cell of the 28 px grid, and the full text for the side panel. The truth
// that wins is marked by a small check glyph with its word in the accessible name, never by a
// colored fill (design/README.md, principle 6).
import { A } from "@solidjs/router";
import { For, Show } from "solid-js";
import { paths } from "../../app/paths";
import { Addr, Mac } from "../../components/Addr";
import { Icon } from "../../components/Icon";
import { ModeBadge, StatusBadge, TimeAgo } from "../../grid/cells";
import { formatList, t } from "../../i18n";
import { TRUTH_WORD, type ReconcileRow, type Truth } from "./model";
import { OsGuess } from "./OsGuess";
import "./truths.css";

const None = () => <span class="muted">–</span>;

/** The check glyph of the truth that wins; its word is the accessible name. */
export function WinsMark() {
  return (
    <span class="wins-mark" role="img" aria-label={t("ipam.reconcile.wins")} title={t("ipam.reconcile.wins")} data-testid="reconcile-wins">
      <Icon name="check" size="xs" />
    </span>
  );
}

/** The MAC addresses of a truth on one line: one in full, several as a count with the list as its tooltip. */
function MacsInline(props: { macs: readonly string[] | undefined }) {
  const list = () => props.macs ?? [];
  return (
    <Show when={list().length > 0} fallback={<None />}>
      <Show when={list().length > 1} fallback={<Mac value={list()[0] ?? ""} />}>
        <span class="mono" title={list().join(", ")}>
          {t("ipam.reconcile.macs_count", { count: list().length })}
        </span>
      </Show>
    </Show>
  );
}

/** What a truth says about the row, as text: for the cell's tooltip and the accessible row name. */
export function truthText(row: ReconcileRow, truth: Truth): string {
  switch (truth) {
    case "intent":
      return row.intent ? [row.intent.host_name, row.intent.dns_name, ...(row.intent.macs ?? [])].filter(Boolean).join(" ") : "";
    case "dns":
      return row.dns ? [...(row.dns.forward ?? []), ...(row.dns.ptr ?? [])].join(" ") : "";
    case "lease":
      return (row.lease?.macs ?? []).join(" ");
    case "scan":
      return (row.scan?.macs ?? []).join(" ");
  }
}

/** One truth in one line, for a cell of the grid, with the check glyph when it wins. */
export function TruthLine(props: { row: ReconcileRow; truth: Truth }) {
  const wins = () => props.row.winner === props.truth;
  const body = () => {
    const row = props.row;
    switch (props.truth) {
      case "intent":
        return (
          <Show when={row.intent} fallback={<None />}>
            {(i) => (
              <>
                <Show when={i().host_name} fallback={<MacsInline macs={i().macs} />}>
                  {(name) => (
                    <A href={paths.host(name())} data-testid="reconcile-host">
                      {name()}
                    </A>
                  )}
                </Show>
                <Show when={i().mode}>{(mode) => <ModeBadge mode={mode()} />}</Show>
              </>
            )}
          </Show>
        );
      case "dns":
        return (
          <Show when={row.dns} fallback={<None />}>
            {(d) => (
              <Show when={(d().forward ?? []).length > 0} fallback={<Show when={(d().ptr ?? []).length > 0} fallback={<None />}>
                <span class="mono" data-testid="reconcile-ptr">{t("ipam.reconcile.ptr_line", { names: (d().ptr ?? []).join(", ") })}</span>
              </Show>}>
                <span class="mono" data-testid="reconcile-forward">
                  {(d().forward ?? []).join(", ")}
                </span>
              </Show>
            )}
          </Show>
        );
      case "lease":
        return <MacsInline macs={row.lease?.macs} />;
      case "scan":
        return <MacsInline macs={row.scan?.macs} />;
    }
  };
  return (
    <span class="truth-line" data-truth={props.truth} data-winner={wins() ? "true" : undefined} title={truthText(props.row, props.truth) || undefined}>
      <Show when={wins()}>
        <WinsMark />
      </Show>
      {body()}
    </span>
  );
}

/** Who wins, in words: "Intent wins", "No winner". */
export function outcomeWord(row: Pick<ReconcileRow, "winner">): string {
  return row.winner ? t("ipam.reconcile.winner", { truth: t(TRUTH_WORD[row.winner]) }) : t("ipam.reconcile.no_winner");
}

function Observed(props: { truth: ReconcileRow["lease"] }) {
  return (
    <Show when={props.truth} fallback={<None />}>
      {(o) => (
        <span class="truth-body">
          <Show when={(o().macs ?? []).length > 0}>
            <span class="reconcile-macs">
              <For each={o().macs}>{(mac) => <Mac value={mac} />}</For>
            </span>
          </Show>
          <Show when={(o().sources ?? []).length > 0}>
            <span class="mono muted">{formatList(o().sources ?? [], "unit")}</span>
          </Show>
          <Show when={o().last_seen}>
            <span class="muted">
              {t("ipam.reconcile.last_seen")} <TimeAgo at={o().last_seen} />
            </span>
          </Show>
        </span>
      )}
    </Show>
  );
}

/** The four truths in full, with the winner marked, the OS field and the vendors: the evidence of the side panel. */
export function TruthList(props: { row: ReconcileRow }) {
  const mark = (truth: Truth) => (
    <Show when={props.row.winner === truth}>
      <WinsMark />
    </Show>
  );
  return (
    <dl class="kv truth-list" data-testid="truth-list">
      <dt>
        {t(TRUTH_WORD.intent)} {mark("intent")}
      </dt>
      <dd>
        <Show when={props.row.intent} fallback={<None />}>
          {(i) => (
            <span class="truth-body">
              <Show when={i().host_name}>
                {(name) => (
                  <A href={paths.host(name())} data-testid="reconcile-host">
                    {name()}
                  </A>
                )}
              </Show>
              <span class="truth-badges">
                <Show when={i().mode}>{(mode) => <ModeBadge mode={mode()} />}</Show>
                <Show when={i().status}>{(status) => <StatusBadge status={status()} />}</Show>
              </span>
              <Show when={i().dns_name}>
                <span class="mono">{i().dns_name}</span>
              </Show>
              <Show when={(i().macs ?? []).length > 0}>
                <span class="reconcile-macs">
                  <For each={i().macs}>{(mac) => <Mac value={mac} />}</For>
                </span>
              </Show>
            </span>
          )}
        </Show>
      </dd>
      <dt>
        {t(TRUTH_WORD.lease)} {mark("lease")}
      </dt>
      <dd>
        <Observed truth={props.row.lease} />
      </dd>
      <dt>
        {t(TRUTH_WORD.dns)} {mark("dns")}
      </dt>
      <dd>
        <Show when={props.row.dns} fallback={<None />}>
          {(d) => (
            <span class="truth-body">
              <Show when={(d().forward ?? []).length > 0}>
                <span class="mono">{(d().forward ?? []).join(", ")}</span>
              </Show>
              <Show when={(d().ptr ?? []).length > 0}>
                <span class="mono">{t("ipam.reconcile.ptr_line", { names: (d().ptr ?? []).join(", ") })}</span>
              </Show>
            </span>
          )}
        </Show>
      </dd>
      <dt>
        {t(TRUTH_WORD.scan)} {mark("scan")}
      </dt>
      <dd>
        <Observed truth={props.row.scan} />
      </dd>
      <Show when={props.row.os}>
        {(os) => (
          <>
            <dt>{t("ipam.reconcile.os")}</dt>
            <dd>
              <OsGuess os={os()} />
            </dd>
          </>
        )}
      </Show>
      <Show when={(props.row.vendors ?? []).length > 0}>
        <dt>{t("ipam.reconcile.vendors")}</dt>
        <dd data-testid="reconcile-vendors">{formatList(props.row.vendors ?? [])}</dd>
      </Show>
      <Show when={props.row.last_seen}>
        <dt>{t("ipam.reconcile.last_seen")}</dt>
        <dd>
          <TimeAgo at={props.row.last_seen} />
        </dd>
      </Show>
      <dt>{t("ipam.reconcile.col.address")}</dt>
      <dd>
        <A href={paths.address(props.row.address, props.row.vrf ?? undefined)} class="mono">
          <Addr value={props.row.address} />
        </A>
      </dd>
    </dl>
  );
}
