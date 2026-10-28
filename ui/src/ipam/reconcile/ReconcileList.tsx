// One list of the reconciliation view: the rows of one kind with the four truths side by side,
// the truth that wins marked, the rule that decided it and, where there is one, the link to the
// proposal. Read page by page over GET /api/v1/ipam/reconcile with the kind, the prefix and the
// host the page filters by; live on the ipam and discovery topics.
import { A } from "@solidjs/router";
import { createEffect, For, Show, type JSX } from "solid-js";
import { paths } from "../../app/paths";
import { Addr, Mac } from "../../components/Addr";
import { ErrorNotice } from "../../components/Notice";
import { ModeBadge, StatusBadge, TimeAgo } from "../../grid/cells";
import { createListSource } from "../../grid/source";
import { formatList, t } from "../../i18n";
import { KIND_HELP, KIND_TITLE, RULE_TEXT, TRUTH_WORD, TRUTHS, type ReconcileKind, type ReconcileRow, type Truth } from "./model";
import { OsGuess } from "./OsGuess";

/** Rows per page of one list. */
const PAGE_SIZE = 50;

const None = () => <span class="muted">–</span>;

function Macs(props: { macs: readonly string[] | undefined }) {
  return (
    <Show when={(props.macs ?? []).length > 0}>
      <span class="reconcile-macs">
        <For each={props.macs}>{(mac) => <Mac value={mac} />}</For>
      </span>
    </Show>
  );
}

function Observed(props: { truth: { macs?: string[] | undefined; sources?: string[] | undefined; last_seen?: string | null | undefined } | null | undefined }) {
  return (
    <Show when={props.truth} fallback={<None />}>
      {(o) => (
        <div class="truth-body">
          <Macs macs={o().macs} />
          <Show when={(o().sources ?? []).length > 0}>
            <span class="mono muted">{formatList(o().sources ?? [], "unit")}</span>
          </Show>
          <Show when={o().last_seen}>
            <span class="muted">
              {t("ipam.reconcile.last_seen")} <TimeAgo at={o().last_seen} />
            </span>
          </Show>
        </div>
      )}
    </Show>
  );
}

function Intent(props: { row: ReconcileRow }) {
  return (
    <Show when={props.row.intent} fallback={<None />}>
      {(i) => (
        <div class="truth-body">
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
          <Macs macs={i().macs} />
        </div>
      )}
    </Show>
  );
}

function Dns(props: { row: ReconcileRow }) {
  return (
    <Show when={props.row.dns} fallback={<None />}>
      {(d) => (
        <dl class="truth-dns">
          <Show when={(d().forward ?? []).length > 0}>
            <dt>{t("ipam.reconcile.dns_forward")}</dt>
            <dd class="mono" data-testid="reconcile-forward">
              {(d().forward ?? []).join(", ")}
            </dd>
          </Show>
          <Show when={(d().ptr ?? []).length > 0}>
            <dt>{t("ipam.reconcile.dns_ptr")}</dt>
            <dd class="mono" data-testid="reconcile-ptr">
              {(d().ptr ?? []).join(", ")}
            </dd>
          </Show>
        </dl>
      )}
    </Show>
  );
}

/** The cell of a truth; the winner is marked with a tag as well as a color. */
function TruthCell(props: { row: ReconcileRow; truth: Truth }) {
  const wins = () => props.row.winner === props.truth;
  return (
    <td class="truth" classList={{ winner: wins() }} data-truth={props.truth} data-winner={wins() ? "true" : undefined}>
      <Show when={wins()}>
        <span class="tag ok wins" data-testid="reconcile-wins">
          {t("ipam.reconcile.wins")}
        </span>
      </Show>
      {props.truth === "intent" ? <Intent row={props.row} /> : props.truth === "dns" ? <Dns row={props.row} /> : <Observed truth={props.truth === "lease" ? props.row.lease : props.row.scan} />}
    </td>
  );
}

function Row(props: { row: ReconcileRow }) {
  return (
    <tr data-testid="reconcile-row" data-key={props.row.key} data-kind={props.row.kind} data-rule={props.row.rule_id} data-winner={props.row.winner ?? "none"}>
      <th scope="row" class="address">
        <A href={paths.address(props.row.address, props.row.vrf ?? undefined)} class="mono">
          <Addr value={props.row.address} />
        </A>
      </th>
      <For each={TRUTHS}>{(truth) => <TruthCell row={props.row} truth={truth} />}</For>
      <td class="decision">
        <strong data-testid="reconcile-winner">
          {props.row.winner ? t("ipam.reconcile.winner", { truth: t(TRUTH_WORD[props.row.winner]) }) : t("ipam.reconcile.no_winner")}
        </strong>
        <span class="rule" data-testid="reconcile-rule">
          {t(RULE_TEXT[props.row.rule_id])}
        </span>
      </td>
      <td class="details">
        <div class="truth-body">
          <Show when={props.row.proposal}>
            {(id) => (
              <A href={paths.proposal(id())} data-testid="reconcile-proposal" data-id={id()}>
                {t("ipam.reconcile.proposal")}
              </A>
            )}
          </Show>
          <Show when={props.row.os}>{(os) => <OsGuess os={os()} />}</Show>
          <Show when={(props.row.vendors ?? []).length > 0}>
            <span data-testid="reconcile-vendors">
              <span class="muted">{t("ipam.reconcile.vendors")}</span> {formatList(props.row.vendors ?? [])}
            </span>
          </Show>
          <Show when={props.row.last_seen}>
            <span class="muted">
              {t("ipam.reconcile.last_seen")} <TimeAgo at={props.row.last_seen} />
            </span>
          </Show>
        </div>
      </td>
    </tr>
  );
}

export function ReconcileList(props: {
  kind: ReconcileKind;
  prefix?: string | undefined;
  host?: string | undefined;
  /** Told the rows read so far and whether there are more, for the count on the kind's chip. */
  onCount?: (count: number, more: boolean) => void;
}): JSX.Element {
  const source = createListSource<ReconcileRow>({
    path: "/api/v1/ipam/reconcile",
    query: () => ({ kind: props.kind, prefix: props.prefix, host: props.host }),
    rowId: (r) => r.key,
    pageSize: PAGE_SIZE,
    topics: ["ipam", "discovery"],
  });
  createEffect(() => {
    if (!source.initial() && !source.error()) props.onCount?.(source.rows().length, source.hasMore());
  });
  const count = () => t("ipam.reconcile.count", { count: source.rows().length, more: source.hasMore() ? "yes" : "no" });
  const title = () => t(KIND_TITLE[props.kind]);

  return (
    <section class="reconcile-list page-section" aria-labelledby={`reconcile-title-${props.kind}`} data-testid={`reconcile-section-${props.kind}`} data-kind={props.kind} data-count={source.initial() ? undefined : source.rows().length}>
      <h2 id={`reconcile-title-${props.kind}`}>
        {title()}
        <Show when={!source.initial() && !source.error()}>
          <span class="count" data-testid="reconcile-count">
            {count()}
          </span>
        </Show>
      </h2>
      <p class="kind-help">{t(KIND_HELP[props.kind])}</p>
      <Show when={source.error()}>
        <ErrorNotice error={source.error()} />
        <div>
          <button type="button" class="btn" data-testid="reconcile-retry" onClick={() => source.reload()}>
            {t("ipam.reconcile.retry")}
          </button>
        </div>
      </Show>
      <Show when={source.initial() && !source.error()}>
        <p class="muted" role="status">
          {t("common.loading")}
        </p>
      </Show>
      <Show when={!source.initial() && !source.error() && source.rows().length === 0}>
        <p class="muted" data-testid="reconcile-empty">
          {t("ipam.reconcile.empty")}
        </p>
      </Show>
      <Show when={source.rows().length > 0}>
        <div class="table-wrap">
          <table class="plain reconcile-table" aria-label={title()}>
            <thead>
              <tr>
                <th scope="col">{t("ipam.reconcile.col.address")}</th>
                <For each={TRUTHS}>{(truth) => <th scope="col">{t(TRUTH_WORD[truth])}</th>}</For>
                <th scope="col">{t("ipam.reconcile.col.winner")}</th>
                <th scope="col">{t("ipam.reconcile.col.details")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={source.rows()}>{(row) => <Row row={row} />}</For>
            </tbody>
          </table>
        </div>
        <Show when={source.hasMore()}>
          <div>
            <button type="button" class="btn" data-testid="reconcile-more" disabled={source.loading()} onClick={() => source.loadMore()}>
              {t("ipam.reconcile.more")}
            </button>
          </div>
        </Show>
      </Show>
    </section>
  );
}
