// The query log of a DNS node (/dns/log, WP5.4): the last queries of the node, newest first,
// with time, client, transport, name, type, RCODE and latency; filters by name (the name and
// the names under it), client, RCODE and time; older pages through the cursor of the node
// command `dns.log.read`. The client is what the node logged: a pseudonym (the default in
// every profile), nothing, or the address, which the server sends only to principals that may
// update the node. Every read is audited by the server. Administrators stop and start the log
// (the kill switch). A node whose log is off shows an empty state that says where it is set.
import { A } from "@solidjs/router";
import { createMemo, createResource, createSignal, createUniqueId, For, Match, Show, Switch } from "solid-js";
import { ApiError, errorMessage } from "../../api/problem";
import { paths } from "../../app/paths";
import { isAdmin } from "../../auth/session";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { ColumnResize, createResizer } from "../../grid/ColumnResize";
import { createColumnWidths } from "../../grid/widths";
import { formatDateTime, formatNumber, t, type MessageKey } from "../../i18n";
import { DnsNav } from "../DnsNav";
import { NodeSelect, useDnsNode } from "../node";
import { DnsProblem, unavailable } from "../Parts";
import { nodeDns, readLog, switchLog, type QueryLogLine, type QueryLogStatus } from "./api";
import { checkFilters, clientKind, filtered, NO_FILTERS, PAGE_SIZE, RCODES, rcodeName, toQuery, type FilterProblem, type LogFilters } from "./model";
// WP10.4: the validation state and the extended error.
import { byValidation, edeName, VALIDATION_STATES, type ValidationState } from "./model";
import "../dns.css";
import "./log.css";

const TIME: Intl.DateTimeFormatOptions = { dateStyle: "short", timeStyle: "medium" };

function notDns(err: unknown): boolean {
  return err instanceof ApiError && err.code === "dns.node.not_dns";
}

function Figures(props: { log: QueryLogStatus }) {
  return (
    <p
      class="dns-log-figures muted"
      data-testid="dns-log-figures"
      data-state={props.log.state}
      data-client={props.log.client}
      data-written={props.log.written}
      data-dropped={props.log.dropped}
    >
      {t("dns.log.figures", {
        client: t(`dns.log.client_mode.${props.log.client === "address" || props.log.client === "hidden" ? props.log.client : "pseudonym"}`),
        sample: props.log.sample,
        days: props.log.days,
        written: props.log.written,
        dropped: props.log.dropped,
      })}
    </p>
  );
}

// WP10.1: how the answer was found, as the node logged it; a line written before it was logged
// shows nothing, and a word this version does not know is shown as the node wrote it.
const RESOLUTIONS = ["zone", "cache", "denial", "stale", "forward", "recurse", "local", "policy", "refused"] as const;

function Resolution(props: { line: QueryLogLine }) {
  const word = () => RESOLUTIONS.find((known) => known === props.line.resolution);
  return (
    <Show when={props.line.resolution}>
      {(raw) => (
        <span class="tag" data-testid="dns-log-resolution" data-resolution={raw()}>
          <Show when={word()} fallback={raw()}>
            {(known) => t(`dns.log.resolution.${known()}`)}
          </Show>
        </span>
      )}
    </Show>
  );
}
// WP10.1: end.

// WP10.4: the validation state of the answer and its extended error; a line written before
// they were logged shows nothing, and a state this version does not know is shown as written.
function Validation(props: { line: QueryLogLine }) {
  const word = () => VALIDATION_STATES.find((known) => known === props.line.validation);
  return (
    <Show when={props.line.validation}>
      {(raw) => (
        <span class="tag" classList={{ conflict: raw() === "bogus" }} data-testid="dns-log-validation" data-state={raw()}>
          <Show when={word()} fallback={raw()}>
            {(known) => t(`dns.log.validation.${known()}`)}
          </Show>
        </span>
      )}
    </Show>
  );
}

function Ede(props: { line: QueryLogLine }) {
  return (
    <Show when={props.line.ede}>
      {(code) => (
        <span class="mono" data-testid="dns-log-ede" data-code={code()} title={edeName(code())}>
          {edeName(code()) ? t("dns.log.ede", { code: code(), name: edeName(code()) ?? "" }) : String(code())}
        </span>
      )}
    </Show>
  );
}
// WP10.4: end.

function Client(props: { line: QueryLogLine }) {
  const kind = () => clientKind(props.line);
  return (
    <Show when={kind() !== "hidden"} fallback={<span class="muted">{t("dns.log.client_none")}</span>}>
      <span class="mono" data-testid="dns-log-client" data-kind={kind()} title={kind() === "pseudonym" ? t("dns.log.pseudonym_hint") : undefined}>
        {props.line.client}
      </span>
    </Show>
  );
}

// The columns of the log: the id is the `data-col` of the cells and the key of their width.
const COLUMNS: readonly { id: string; header: MessageKey; right?: boolean }[] = [
  { id: "time", header: "dns.log.col.time" },
  { id: "client", header: "dns.log.col.client" },
  { id: "transport", header: "dns.log.col.transport" },
  { id: "name", header: "dns.log.col.name" },
  { id: "type", header: "dns.log.col.type" },
  { id: "rcode", header: "dns.log.col.rcode" },
  // WP10.1: how the answer was found and what the resolver asked for it.
  { id: "resolution", header: "dns.log.col.resolution" },
  { id: "subqueries", header: "dns.log.col.subqueries", right: true },
  // WP10.1: end.
  // WP10.4: the validation state and the extended error.
  { id: "validation", header: "dns.log.col.validation" },
  { id: "ede", header: "dns.log.col.ede" },
  // WP10.4: end.
  { id: "latency", header: "dns.log.col.latency", right: true },
  { id: "flags", header: "dns.log.col.flags" },
];

function Lines(props: { lines: QueryLogLine[] }) {
  let table!: HTMLTableElement;
  const ids = createUniqueId();
  // The column widths the user set on the header handles, kept like those of the grids.
  const widths = createColumnWidths("dns-log");
  const resizer = createResizer({ widths, columns: () => COLUMNS, table: () => table });
  return (
    <div>
      <div class="table-wrap">
        <table
          ref={table}
          class="plain resizable dns-log-table"
          classList={{ sized: widths.custom() }}
          style={resizer.tableWidth() ? { width: resizer.tableWidth() } : undefined}
          data-testid="dns-log-table"
        >
          <caption class="sr-only">{t("dns.log.table")}</caption>
          <colgroup>
            <For each={COLUMNS}>
              {(c) => {
                const width = () => resizer.colWidth(c.id);
                return <col style={width() ? { width: `${width()}px` } : undefined} />;
              }}
            </For>
          </colgroup>
          <thead>
            <tr>
              <For each={COLUMNS}>
                {(c) => (
                  <th scope="col" class={c.right ? "r" : undefined} data-col={c.id} aria-labelledby={`${ids}-${c.id}`}>
                    <span id={`${ids}-${c.id}`}>{t(c.header)}</span>
                    <Show when={resizer.enabled()}>
                      <ColumnResize resizer={resizer} column={c.id} label={t("grid.resize.handle", { column: t(c.header) })} />
                    </Show>
                  </th>
                )}
              </For>
            </tr>
          </thead>
          <tbody>
            <For each={props.lines}>
              {(line, index) => (
                <tr data-testid="dns-log-row" data-index={index()} data-key={line.qname} data-rcode={line.rcode}>
                  <td data-col="time" class="nowrap">
                    {formatDateTime(line.at, TIME)}
                  </td>
                  <td data-col="client">
                    <Client line={line} />
                  </td>
                  <td data-col="transport">{t(`dns.log.transport.${line.transport}`)}</td>
                  <td data-col="name" class="mono">
                    {line.qname}
                  </td>
                  <td data-col="type" class="mono">
                    {line.type}
                  </td>
                  <td data-col="rcode" class="mono">
                    <span class={line.rcode === 0 ? undefined : "dns-log-bad"}>{rcodeName(line.rcode)}</span>
                  </td>
                  {/* WP10.1: the resolution and the sub-queries. */}
                  <td data-col="resolution">
                    <Resolution line={line} />
                  </td>
                  <td data-col="subqueries" class="r">
                    <Show when={line.subqueries}>{(count) => formatNumber(count())}</Show>
                  </td>
                  {/* WP10.1: end. */}
                  {/* WP10.4: the validation state and the extended error. */}
                  <td data-col="validation">
                    <Validation line={line} />
                  </td>
                  <td data-col="ede" class="nowrap">
                    <Ede line={line} />
                  </td>
                  <td data-col="latency" class="r nowrap">
                    {t("dns.log.latency", { ms: formatNumber(line.duration_micros / 1000, { maximumFractionDigits: 2 }) })}
                  </td>
                  <td data-col="flags">
                    <Show when={line.cached}>
                      <span class="tag" data-testid="dns-log-cached">
                        {t("dns.log.cached")}
                      </span>
                    </Show>
                    <Show when={line.blocked}>
                      <span class="tag conflict" data-testid="dns-log-blocked">
                        {t("dns.log.blocked")}
                      </span>
                    </Show>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>
      <Show when={widths.custom()}>
        <div class="dns-log-widths">
          <button type="button" class="btn sm ghost" data-testid="dns-log-reset-widths" onClick={() => widths.reset()}>
            {t("grid.resize.reset")}
          </button>
        </div>
      </Show>
    </div>
  );
}

export default function LogPage() {
  const { nodes, node, choose } = useDnsNode();
  const [status, { refetch: refetchStatus }] = createResource(node, (id) => nodeDns(id));
  const log = () => (status.error ? undefined : status.latest?.query_log ?? undefined);

  // WP10.4: the validation state the lines of the page shown are narrowed to (the node's log
  // read has no such filter, so it applies to the page as read).
  const [validation, setValidation] = createSignal<ValidationState | "">("");
  // The form as typed, and the filters of the pages shown.
  const [draft, setDraft] = createSignal<LogFilters>({ ...NO_FILTERS });
  const [applied, setApplied] = createSignal<LogFilters>({ ...NO_FILTERS });
  const [problems, setProblems] = createSignal<FilterProblem[]>([]);
  // The cursors of the pages from the newest to the one shown (undefined: the newest page).
  const [cursors, setCursors] = createSignal<(string | undefined)[]>([undefined]);
  const [tick, setTick] = createSignal(0);
  const [busy, setBusy] = createSignal(false);

  const request = createMemo(() => {
    const id = node();
    if (id === undefined || !log()) return undefined;
    const stack = cursors();
    return { id, query: toQuery(applied(), stack[stack.length - 1]), tick: tick() };
  });
  const [page] = createResource(request, (r) => readLog(r.id, r.query));

  const field = (name: keyof LogFilters) => (event: { currentTarget: { value: string } }) => setDraft({ ...draft(), [name]: event.currentTarget.value });

  const apply = (event: Event) => {
    event.preventDefault();
    const found = checkFilters(draft());
    setProblems(found);
    if (found.length > 0) return;
    setApplied({ ...draft() });
    setCursors([undefined]);
    setTick(tick() + 1);
  };
  const reset = () => {
    setDraft({ ...NO_FILTERS });
    setApplied({ ...NO_FILTERS });
    setProblems([]);
    setCursors([undefined]);
  };
  const older = () => {
    const next = page.latest?.next;
    if (next) setCursors([...cursors(), next]);
  };
  const newer = () => setCursors(cursors().slice(0, -1));
  const refresh = () => {
    void refetchStatus();
    setCursors([undefined]);
    setTick(tick() + 1);
  };

  const toggle = async (stop: boolean) => {
    const id = node();
    if (id === undefined || busy()) return;
    setBusy(true);
    try {
      await switchLog(id, stop);
      toast({ kind: "ok", title: stop ? t("dns.log.stopped_toast") : t("dns.log.started_toast") });
      void refetchStatus();
    } catch (err) {
      toast({ kind: "bad", title: t("dns.log.switch_failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  const problem = (name: FilterProblem) => problems().includes(name);
  const short = () => {
    const current = page.latest;
    return !!current && !!current.next && current.items.length < PAGE_SIZE;
  };

  return (
    <div class="page dns-page" data-testid="page-dns-log">
      <DnsNav />
      <PageHead
        title={t("dns.log.title")}
        sub={t("dns.log.sub")}
        actions={
          <>
            <Show when={log()}>
              <button type="button" class="btn" data-testid="dns-log-refresh" onClick={refresh}>
                <Icon name="refresh" />
                {t("dns.log.refresh")}
              </button>
            </Show>
            <Show when={isAdmin() && log()}>
              {(current) => (
                <Show
                  when={current().state === "on"}
                  fallback={
                    <button type="button" class="btn primary" data-testid="dns-log-start" disabled={busy()} onClick={() => void toggle(false)}>
                      {t("dns.log.start")}
                    </button>
                  }
                >
                  <button type="button" class="btn" data-testid="dns-log-stop" disabled={busy()} onClick={() => void toggle(true)}>
                    {t("dns.log.stop")}
                  </button>
                </Show>
              )}
            </Show>
          </>
        }
      />
      <div class="page-body dns-log-body">
        <Show when={nodes.error}>
          <ErrorNotice error={nodes.error} />
        </Show>
        <Show when={nodes.latest && nodes.latest.length === 0}>
          <Notice kind="info" role="status" testid="dns-log-no-node">
            {t("dns.log.no_node")}
          </Notice>
        </Show>
        <Show when={(nodes.latest?.length ?? 0) > 0}>
          <NodeSelect nodes={nodes.latest ?? []} node={node()} onChoose={choose} />
        </Show>
        <Switch>
          <Match when={status.error && unavailable(status.error)}>
            <DnsProblem error={status.error} />
          </Match>
          <Match when={status.error && notDns(status.error)}>
            <Notice kind="info" role="status" title={t("dns.log.not_dns_title")} testid="dns-log-not-dns">
              {t("dns.log.not_dns_body")}
            </Notice>
          </Match>
          <Match when={status.error}>
            <ErrorNotice error={status.error} />
          </Match>
          <Match when={status.latest && !status.latest.query_log}>
            <div class="empty" data-testid="dns-log-off">
              <h2>{t("dns.log.off_title")}</h2>
              <p>{t("dns.log.off_body")}</p>
              <A class="btn" href={paths.settings("security")} data-testid="dns-log-settings-link">
                {t("dns.log.off_link")}
              </A>
            </div>
          </Match>
          <Match when={log()}>
            {(current) => (
              <>
                <Show when={current().state === "stopped"}>
                  <Notice kind="warn" role="status" title={t("dns.log.stopped_title")} testid="dns-log-stopped">
                    {t("dns.log.stopped_body")}
                  </Notice>
                </Show>
                <Figures log={current()} />
                <form class="dns-log-filters" data-testid="dns-log-filters" onSubmit={apply} novalidate>
                  <div class="field">
                    <label for="dns-log-qname">{t("dns.log.filter.qname")}</label>
                    <input
                      id="dns-log-qname"
                      class="input mono"
                      value={draft().qname}
                      placeholder={t("dns.log.filter.qname_placeholder")}
                      spellcheck={false}
                      autocomplete="off"
                      aria-invalid={problem("qname") ? "true" : undefined}
                      data-testid="field-qname"
                      onInput={field("qname")}
                    />
                    <Show when={problem("qname")}>
                      <span class="help bad" data-testid="field-error" data-field="qname">
                        {t("dns.log.filter.qname_invalid")}
                      </span>
                    </Show>
                  </div>
                  <div class="field">
                    <label for="dns-log-client">{t("dns.log.filter.client")}</label>
                    <input
                      id="dns-log-client"
                      class="input mono"
                      value={draft().client}
                      placeholder={t("dns.log.filter.client_placeholder")}
                      spellcheck={false}
                      autocomplete="off"
                      aria-invalid={problem("client") ? "true" : undefined}
                      data-testid="field-client"
                      onInput={field("client")}
                    />
                    <Show when={problem("client")}>
                      <span class="help bad" data-testid="field-error" data-field="client">
                        {t("dns.log.filter.client_invalid")}
                      </span>
                    </Show>
                  </div>
                  <div class="field">
                    <label for="dns-log-rcode">{t("dns.log.filter.rcode")}</label>
                    <select id="dns-log-rcode" class="select" value={draft().rcode} data-testid="field-rcode" onChange={field("rcode")}>
                      <option value="">{t("dns.log.filter.rcode_any")}</option>
                      <For each={RCODES}>{([code, name]) => <option value={String(code)}>{name}</option>}</For>
                    </select>
                  </div>
                  {/* WP10.4: the validation state, applied to the page shown at once. */}
                  <div class="field">
                    <label for="dns-log-validation">{t("dns.log.filter.validation")}</label>
                    <select
                      id="dns-log-validation"
                      class="select"
                      value={validation()}
                      aria-describedby="dns-log-validation-help"
                      data-testid="field-validation"
                      onChange={(event) => setValidation(event.currentTarget.value as ValidationState | "")}
                    >
                      <option value="">{t("dns.log.filter.validation_any")}</option>
                      <For each={VALIDATION_STATES}>{(state) => <option value={state}>{t(`dns.log.validation.${state}`)}</option>}</For>
                    </select>
                    <span class="help" id="dns-log-validation-help">
                      {t("dns.log.filter.validation_help")}
                    </span>
                  </div>
                  <div class="field">
                    <label for="dns-log-from">{t("dns.log.filter.from")}</label>
                    <input id="dns-log-from" type="datetime-local" class="input" value={draft().from} data-testid="field-from" onInput={field("from")} />
                  </div>
                  <div class="field">
                    <label for="dns-log-until">{t("dns.log.filter.until")}</label>
                    <input
                      id="dns-log-until"
                      type="datetime-local"
                      class="input"
                      value={draft().until}
                      aria-invalid={problem("until") ? "true" : undefined}
                      data-testid="field-until"
                      onInput={field("until")}
                    />
                    <Show when={problem("until")}>
                      <span class="help bad" data-testid="field-error" data-field="until">
                        {t("dns.log.filter.until_invalid")}
                      </span>
                    </Show>
                  </div>
                  <div class="dns-log-filter-actions">
                    <button type="submit" class="btn primary" data-testid="form-submit">
                      {t("dns.log.filter.apply")}
                    </button>
                    <Show when={filtered(applied()) || filtered(draft())}>
                      <button type="button" class="btn" data-testid="dns-log-reset" onClick={reset}>
                        {t("dns.log.filter.reset")}
                      </button>
                    </Show>
                  </div>
                </form>
                <Show when={page.error}>
                  <ErrorNotice error={page.error} />
                </Show>
                <Show when={!page.error && page.latest}>
                  {(current) => (
                    <Show
                      when={current().items.length > 0}
                      fallback={
                        <div class="empty" data-testid="dns-log-empty" data-filtered={filtered(applied()) ? "true" : "false"}>
                          <h3>{filtered(applied()) ? t("dns.log.empty_filtered") : t("dns.log.empty")}</h3>
                        </div>
                      }
                    >
                      {/* WP10.4: narrowed to the validation state chosen. */}
                      <Show
                        when={byValidation(current().items, validation()).length > 0}
                        fallback={
                          <div class="empty" data-testid="dns-log-empty-validation">
                            <h3>{t("dns.log.empty_validation")}</h3>
                          </div>
                        }
                      >
                        <Lines lines={byValidation(current().items, validation())} />
                      </Show>
                    </Show>
                  )}
                </Show>
                <Show when={short()}>
                  <p class="muted" data-testid="dns-log-partial">
                    {t("dns.log.partial")}
                  </p>
                </Show>
                <div class="dns-log-paging" data-testid="dns-log-paging" data-page={cursors().length}>
                  <button type="button" class="btn" data-testid="dns-log-newer" disabled={cursors().length <= 1 || page.loading} onClick={newer}>
                    {t("dns.log.newer")}
                  </button>
                  <span class="muted">{t("dns.log.page", { page: cursors().length })}</span>
                  <button type="button" class="btn" data-testid="dns-log-older" disabled={!page.latest?.next || page.loading} onClick={older}>
                    {t("dns.log.older")}
                  </button>
                </div>
              </>
            )}
          </Match>
        </Switch>
      </div>
    </div>
  );
}
