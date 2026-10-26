// The move preview (IPAM-19, design decisions 6 to 8): a page of its own, reached by dropping
// hosts or addresses on a network of the tree or with M. Per device it shows the old and the
// new address (the same host part when it is free, else the next free address by the
// network's policy), the DNS change, the network (L2) step and the manual steps; below, one
// grouped checklist of every manual task of the whole batch. Nothing changes until "Start"
// is confirmed: then one job per device starts, all in one group with the chosen
// parallelism, and the page hands over to the jobs list of that group. Per device the
// DHCP timing column shows the two times (the client's next expected DHCP activity and the
// migration deadline, each with where it comes from) and what the job does before the network
// change: it waits for the next renewal, which gets a short lease, or, with "Move now", changes
// the network at once. The migration deadline rolls a device back on expiry; the longest one
// of the batch is the default of the timeout choice.
//
// The network (L2) column says per device what happens: a port profile or a per-client VLAN
// through the network controller, nothing (in the VLAN already, or moving with another
// address of the interface), or by hand with the reason; the expanded row has the diff, the
// notes and the SSID alternative. A line above the table names the controllers that were
// read. Start confirms the fingerprint of the preview: when the plan changed meanwhile
// (409), the page previews again at once and says so.
import { A, useNavigate, useSearchParams } from "@solidjs/router";
import { createEffect, createMemo, createSignal, For, on, onCleanup, onMount, Show } from "solid-js";
import { newIdempotencyKey } from "../../api/client";
import { isApiError } from "../../api/problem";
import { previewMove, submitMove, type MoveItem, type MovePreview as Preview } from "../../api/moves";
import type { ObjectRef } from "../../api/types";
import { paths } from "../../app/paths";
import { may } from "../../auth/gate";
import { Addr } from "../../components/Addr";
import { Icon } from "../../components/Icon";
import { Kbd } from "../../components/Kbd";
import { ErrorNotice, Notice } from "../../components/Notice";
import { Segmented } from "../../components/Segmented";
import { Switch } from "../../components/Switch";
import { toast } from "../../components/toast";
import { DnsName, ModeBadge } from "../../grid/cells";
import { formatDuration, t } from "../../i18n";
import { IpamNav } from "../IpamNav";
import { warningText } from "../plan/describe";
import {
  activitySourceText,
  deadlineSourceText,
  deviceName,
  groupTitle,
  L2_REASON,
  L2_REFUSED_WARNING,
  l2Detail,
  l2DiffText,
  l2Headline,
  l2NoteText,
  l2SsidsText,
  leaseSpanText,
  nudgeText,
  PLAN_CHANGED,
  prepareText,
  reasonText,
  STEP_ORDER,
  stepText,
  timeoutText,
  whenText,
} from "./moveText";
import "./move.css";

const PARALLELISM = ["1", "2", "4", "8"] as const;
const TIMEOUTS = [300, 1800, 3600, 14_400, 43_200, 86_400] as const;

/** Parses `host:<id>,address:<id>` into object references. */
export function parseObjects(text: string | undefined): ObjectRef[] {
  if (!text) return [];
  return text
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const i = part.indexOf(":");
      return { kind: part.slice(0, i), id: part.slice(i + 1) } as ObjectRef;
    })
    .filter((o) => (o.kind === "host" || o.kind === "address") && o.id !== "");
}

const sameRef = (a: ObjectRef, b: ObjectRef) => a.kind === b.kind && a.id === b.id;

/**
 * The network change of one device, compact: what happens in the first line, why or through
 * which controller in a muted second line. The cell carries the decision for tests and
 * scripts (`data-action`, `data-reason`). A server without L2 decisions shows the step text.
 */
function L2Cell(props: { item: MoveItem; preview: Preview; legacy: string }) {
  const l2 = () => props.item.l2;
  // "Moves with {ip}": the old address of the item whose address this one shares the device with.
  const withIp = () => {
    const other = l2()?.with;
    return other ? props.preview.items.find((i) => i.object.id === other)?.old_ip : undefined;
  };
  return (
    <td data-col="l2" data-testid="move-l2" data-action={l2()?.action} data-reason={l2()?.reason ?? undefined}>
      <Show when={l2()} fallback={<span class="l2m">{props.legacy}</span>}>
        {(x) => (
          <div class="l2c">
            <span class="l2m">
              <span class="l2h">{l2Headline(x(), props.preview, withIp())}</span>
              <Show when={x().reason === L2_REASON.refused}>
                <span class="tag discrepancy">{t("move.l2.action.refused")}</span>
              </Show>
            </span>
            <Show when={l2Detail(x(), props.preview)}>
              {(detail) => (
                <span class="l2s" title={detail()}>
                  {detail()}
                </span>
              )}
            </Show>
            <Show when={x().nudge}>
              {(nudge) => (
                <span class="l2s" data-testid="move-nudge" data-action={nudge().action} data-reason={nudge().reason ?? undefined} title={nudgeText(nudge(), x())}>
                  {nudgeText(nudge(), x())}
                </span>
              )}
            </Show>
          </div>
        )}
      </Show>
    </td>
  );
}

/**
 * The two times of one device, compact: the client's next expected DHCP activity (the time,
 * relative and absolute, and where it comes from) and the migration deadline (the duration and
 * how it was chosen), then what the job does before the network change. The cell carries the
 * preparation and the two sources for tests and scripts.
 */
function TimingCell(props: { item: MoveItem }) {
  const timing = () => props.item.timing;
  return (
    <td
      data-col="timing"
      data-testid="move-timing"
      data-prepare={timing()?.prepare}
      data-activity-source={timing()?.next_activity_source}
      data-deadline-source={timing()?.deadline_source}
    >
      <Show when={timing()} fallback={<span class="muted">–</span>}>
        {(x) => (
          <dl class="tmc">
            <dt>{t("move.timing.next")}</dt>
            <dd data-testid="move-next-activity">
              <Show when={x().next_activity} fallback={<span class="muted">{t("move.timing.next_unknown")}</span>}>
                {(at) => <time dateTime={at()}>{whenText(at())}</time>}
              </Show>
              <span class="tag" data-source={x().next_activity_source}>
                {activitySourceText(x().next_activity_source)}
              </span>
            </dd>
            <dt>{t("move.timing.deadline")}</dt>
            <dd data-testid="move-deadline">
              <span>{formatDuration(x().deadline_secs)}</span>
              <span class="tag" data-source={x().deadline_source}>
                {deadlineSourceText(x().deadline_source)}
              </span>
            </dd>
            <dd class="tmp" data-testid="move-prepare">
              {prepareText(x())}
            </dd>
          </dl>
        )}
      </Show>
    </td>
  );
}

/** The client's lease on its old network in the expanded row, when Tenko holds one. */
function LeaseDetail(props: { item: MoveItem }) {
  const span = () => {
    const x = props.item.timing;
    return x?.lease_start && x.lease_end ? leaseSpanText(x.lease_start, x.lease_end) : undefined;
  };
  return (
    <Show when={span()}>
      {(text) => (
        <p class="l2d tml" data-testid="move-lease-span">
          {text()}
        </p>
      )}
    </Show>
  );
}

/** The details of the network change in the expanded row: the diff, the notes and the SSID alternative. */
function L2Details(props: { item: MoveItem; preview: Preview }) {
  const l2 = () => props.item.l2;
  const diff = () => l2()?.diff ?? [];
  const notes = () => l2()?.notes ?? [];
  const ssids = () => {
    const x = l2();
    return x ? l2SsidsText(x, props.preview) : undefined;
  };
  return (
    <Show when={diff().length > 0 || notes().length > 0 || ssids()}>
      <div class="l2d" role="group" aria-label={t("move.col.l2")} data-testid="move-l2-details">
        <Show when={diff().length > 0}>
          <table class="l2diff" data-testid="move-l2-diff">
            <caption class="sr-only">{t("jobs.l2.diff")}</caption>
            <tbody>
              <For each={diff()}>
                {(line) => (
                  <tr>
                    <th scope="row">
                      <code class="mono">{line.path}</code>
                    </th>
                    <td>{l2DiffText(line.before, line.after)}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
        <Show when={notes().length > 0}>
          <ul class="l2notes" data-testid="move-l2-notes">
            <For each={notes()}>{(code) => <li data-note={code}>{l2NoteText(code, props.preview)}</li>}</For>
          </ul>
        </Show>
        <Show when={ssids()}>{(text) => <p class="l2ssids">{text()}</p>}</Show>
      </div>
    </Show>
  );
}

export default function MovePreview() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const target = () => (typeof params.target === "string" ? params.target : "");
  const requested = createMemo(() => parseObjects(typeof params.objects === "string" ? params.objects : undefined));

  const [excluded, setExcluded] = createSignal<ObjectRef[]>([]);
  const [parallelism, setParallelism] = createSignal<string>("2");
  const [timeout, setTimeout_] = createSignal<number | null>(null);
  // Change the network at once, not after the client's next renewal with a short lease.
  const [moveNow, setMoveNow] = createSignal(false);
  // Bounce the client's switch port or disconnect it from its access point when it does not come
  // back by itself after the network change (ADR 0028); on unless the request says otherwise.
  const [nudge, setNudge] = createSignal(true);
  const [acked, setAcked] = createSignal<ReadonlySet<string>>(new Set());
  const [preview, setPreview] = createSignal<Preview | null>(null);
  const [error, setError] = createSignal<unknown>(null);
  const [loading, setLoading] = createSignal(false);
  const [starting, setStarting] = createSignal(false);
  const [open, setOpen] = createSignal<ReadonlySet<string>>(new Set());
  const [allOpen, setAllOpen] = createSignal(false);
  // The plan changed between the preview and Start (409): the page has previewed again.
  const [planChanged, setPlanChanged] = createSignal(false);
  // Counts the previews asked for without a change of the inputs.
  const [again, setAgain] = createSignal(0);
  let key = newIdempotencyKey();
  let controller: AbortController | undefined;
  let lastInputs = "";

  const included = createMemo(() => requested().filter((o) => !excluded().some((x) => sameRef(x, o))));

  const request = () => ({
    objects: included(),
    target: target(),
    timeout_secs: timeout(),
    parallelism: Number(parallelism()),
    move_now: moveNow(),
    ...(nudge() ? {} : { nudge: false }),
    acknowledge: [...acked()],
  });

  // Every change of the inputs previews again; a new preview means a new confirmation.
  createEffect(
    on(
      () => [JSON.stringify(request()), again()] as const,
      async ([inputs]) => {
        // The notice about a changed plan stays until the person changes something or starts.
        if (inputs !== lastInputs) {
          lastInputs = inputs;
          setPlanChanged(false);
        }
        key = newIdempotencyKey();
        controller?.abort();
        if (!target() || included().length === 0) {
          setPreview(null);
          return;
        }
        controller = new AbortController();
        setLoading(true);
        setError(null);
        try {
          setPreview(await previewMove(request(), controller.signal));
        } catch (err) {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError(err);
        } finally {
          setLoading(false);
        }
      },
    ),
  );
  onCleanup(() => controller?.abort());

  // The first preview tells the parallelism the server would use.
  let seededParallelism = false;
  createEffect(() => {
    const p = preview();
    if (p && !seededParallelism) {
      seededParallelism = true;
      if (PARALLELISM.includes(String(p.parallelism) as (typeof PARALLELISM)[number])) setParallelism(String(p.parallelism));
    }
  });

  const items = () => preview()?.items ?? [];
  const itemKey = (item: MoveItem) => `${item.requested.kind}:${item.requested.id}`;
  const isOpen = (item: MoveItem) => allOpen() || open().has(itemKey(item));
  const toggleOpen = (item: MoveItem) => {
    const next = new Set(open());
    if (next.has(itemKey(item))) next.delete(itemKey(item));
    else next.add(itemKey(item));
    setOpen(next);
  };
  const isExcluded = (ref: ObjectRef) => excluded().some((x) => sameRef(x, ref));
  const toggleInclude = (ref: ObjectRef) =>
    setExcluded(isExcluded(ref) ? excluded().filter((x) => !sameRef(x, ref)) : [...excluded(), ref]);

  /** Every manual task of the batch, grouped by step kind in the order of the job. */
  const checklist = createMemo(() => {
    const p = preview();
    if (!p) return [];
    return STEP_ORDER.map((kind) => ({
      kind,
      tasks: p.items.flatMap((item) =>
        item.steps.filter((s) => s.kind === kind && !s.automatic).map((s) => ({ item, text: stepText(s, item, p) })),
      ),
    })).filter((g) => g.tasks.length > 0);
  });
  const manualCount = (item: MoveItem) => item.steps.filter((s) => !s.automatic).length;
  const l2Step = (item: MoveItem) => item.steps.find((s) => s.kind === "l2.move" || s.kind === "l2.controller");
  const blocking = () => (preview()?.unacknowledged ?? []).filter((c) => !acked().has(c));
  // The apply button is for a principal who may change every moved object and the target prefix;
  // the preview itself stays readable for anybody who may read them.
  const mayApply = () =>
    may.job({ id: "move", targets: [...included(), { kind: "prefix", id: target() }] });
  const canStart = () => mayApply() && !!preview() && !loading() && !starting() && blocking().length === 0 && included().length > 0;

  const start = async () => {
    if (!canStart()) return;
    const fingerprint = preview()?.fingerprint;
    setStarting(true);
    setError(null);
    setPlanChanged(false);
    try {
      // The server runs the confirmed plan or nothing: it compares this fingerprint with its own plan.
      const body = fingerprint ? { ...request(), expect_fingerprint: fingerprint } : request();
      const result = await submitMove(body, key);
      const count = result.jobs.length;
      toast({
        kind: "ok",
        title: t("move.started", { count }),
        actions: [{ label: t("move.open_jobs"), run: () => navigate(paths.jobs({ group: result.group })) }],
      });
      navigate(paths.jobs({ group: result.group }), { replace: true });
    } catch (err) {
      setStarting(false);
      if (isApiError(err, PLAN_CHANGED)) {
        // Nothing started: show the plan as it is now and ask for a new confirmation.
        setPlanChanged(true);
        setAgain(again() + 1);
      } else {
        setError(err);
      }
    }
  };

  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        void start();
      }
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  const onRowKey = (e: KeyboardEvent, item: MoveItem) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === " ") {
      e.preventDefault();
      toggleInclude(item.requested);
    } else if (e.key === "Enter") {
      e.preventDefault();
      toggleOpen(item);
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const rows = Array.from(document.querySelectorAll<HTMLElement>("tr.move-row"));
      const i = rows.indexOf(e.currentTarget as HTMLElement);
      rows[e.key === "ArrowDown" ? i + 1 : i - 1]?.focus();
    }
  };

  return (
    <div class="page move-page" data-testid="page-move-preview">
      <IpamNav />
      <div class="page-head">
        <div>
          <nav class="crumbs" aria-label={t("ipam.prefix.crumbs")}>
            <A href={paths.ipam()}>{t("ipam.nav.networks")}</A>
            <Show when={preview()}>
              {(p) => (
                <>
                  <Icon name="chev-r" />
                  <A href={paths.prefix(p().target.cidr)}>{p().target.cidr}</A>
                </>
              )}
            </Show>
            <Icon name="chev-r" />
            <span>{t("move.title")}</span>
          </nav>
          <h1 tabIndex={-1}>
            <span>
              {t("move.heading", { count: included().length })} <Addr value={preview()?.target.cidr ?? ""} />
            </span>
            <Show when={preview()?.target.vid != null}>
              <span class="sub">{t("move.heading_vlan", { vid: preview()?.target.vid ?? 0 })}</span>
            </Show>
          </h1>
        </div>
        <div class="actions">
          <span class="pv-state" role="status">
            {t("move.preview_only")}
          </span>
        </div>
      </div>

      <div class="move-scroll">
        <Notice kind="info">
          <strong>{t("move.phase1_title")}</strong> {t("move.phase1_body")}
        </Notice>
        <Show when={requested().length === 0 || !target()}>
          <Notice kind="bad" role="alert">
            {t("move.nothing")}
          </Notice>
        </Show>
        <ErrorNotice error={error()} />
        <Show when={planChanged()}>
          <Notice kind="warn" role="status" testid="move-plan-changed">
            {t("move.plan_changed")}
          </Notice>
        </Show>
        <Show when={(preview()?.warnings?.length ?? 0) > 0}>
          <div class="move-warnings" data-testid="move-warnings">
            <For each={preview()?.warnings ?? []}>
              {(w) => (
                <Notice kind={w.requires_ack ? "warn" : "info"}>
                  <p>{warningText(w)}</p>
                  <Show when={w.requires_ack}>
                    <label class="ackrow">
                      <input
                        type="checkbox"
                        class="cb"
                        checked={acked().has(w.code)}
                        onChange={(e) => {
                          const next = new Set(acked());
                          if (e.currentTarget.checked) next.add(w.code);
                          else next.delete(w.code);
                          setAcked(next);
                        }}
                      />
                      {t("ipam.plan.ack")}
                    </label>
                  </Show>
                </Notice>
              )}
            </For>
          </div>
        </Show>

        <div class="tools">
          <h2>{t("move.devices")}</h2>
          <span class="count">{t("move.included", { count: included().length, total: requested().length })}</span>
          <div class="right">
            <span class="legend2">
              <span class="auto">{t("move.legend.auto")}</span>
              <span class="manual">{t("move.legend.manual")}</span>
            </span>
            <span class="keys">
              <Kbd keys={["↑", "↓"]} /> {t("move.keys.move")} <Kbd keys={["Space"]} /> {t("move.keys.include")}{" "}
              <Kbd keys={["Enter"]} /> {t("move.keys.steps")}
            </span>
            <button
              type="button"
              class="btn sm ghost"
              data-testid="move-show-steps"
              aria-pressed={allOpen()}
              onClick={() => setAllOpen(!allOpen())}
            >
              {t("move.show_all_steps")}
            </button>
          </div>
        </div>

        <Show when={preview()}>
          {(p) => (
            <p class="l2sum" data-testid="move-controllers">
              <Icon name="router" size="xs" />
              <Show when={(p().controllers ?? []).length > 0} fallback={<span class="ctl off">{t("move.l2.no_controller")}</span>}>
                <For each={p().controllers ?? []}>
                  {(c) => (
                    <span class="ctl" classList={{ off: !c.writes_enabled }} data-writes={c.writes_enabled ? "on" : "off"}>
                      {c.writes_enabled ? t("move.l2.controller", { name: c.name }) : t("move.l2.controller_read_only", { name: c.name })}
                    </span>
                  )}
                </For>
              </Show>
            </p>
          )}
        </Show>

        <table class="grid grouped pvt" aria-label={t("move.devices")} aria-busy={loading() ? "true" : undefined} data-testid="move-devices">
          <colgroup>
            <col class="c-check" />
            <col class="c-device" />
            <col class="c-mode" />
            <col class="c-ip" />
            <col class="c-dns" />
            <col class="c-l2" />
            <col class="c-timing" />
            <col class="c-manual" />
          </colgroup>
          <thead>
            <tr>
              <th class="check" scope="col">
                <span class="sr-only">{t("move.col.include")}</span>
              </th>
              <th scope="col">{t("move.col.device")}</th>
              <th scope="col">{t("ipam.col.mode")}</th>
              <th scope="col">{t("move.col.ip")}</th>
              <th scope="col">{t("move.col.dns")}</th>
              <th scope="col">{t("move.col.l2")}</th>
              <th scope="col">{t("move.col.timing")}</th>
              <th scope="col">{t("move.col.manual")}</th>
            </tr>
          </thead>
          <For each={items()}>
            {(item) => (
              <tbody data-testid="move-item" data-key={deviceName(item)} data-id={item.requested.id}>
                <tr class="move-row" tabIndex={0} onKeyDown={(e) => onRowKey(e, item)}>
                  <td class="check">
                    <input
                      type="checkbox"
                      class="cb"
                      tabIndex={-1}
                      checked={!isExcluded(item.requested)}
                      aria-label={t("move.include", { name: deviceName(item) })}
                      onChange={() => toggleInclude(item.requested)}
                    />
                  </td>
                  <td data-col="device">
                    <span class="devcell">
                      <button
                        type="button"
                        class="twisty"
                        data-testid="move-steps-toggle"
                        tabIndex={-1}
                        aria-expanded={isOpen(item)}
                        aria-label={t("move.show_steps", { name: deviceName(item) })}
                        onClick={() => toggleOpen(item)}
                      >
                        <Icon name={isOpen(item) ? "chev-d" : "chev-r"} size="xs" />
                      </button>
                      <span class="nm">{deviceName(item)}</span>
                    </span>
                  </td>
                  <td data-col="mode">
                    <Show when={item.mode}>{(m) => <ModeBadge mode={m()} />}</Show>
                  </td>
                  <td data-col="ip">
                    <span class="chg">
                      <Addr value={item.old_ip} />
                      <Icon name="arrow-r" size="xs" />
                      <Addr value={item.new_ip} />
                      <Show when={!item.same_host_part}>
                        <span class="tag discrepancy" title={reasonText(item)}>
                          {t("move.other_host_part")}
                        </span>
                      </Show>
                    </span>
                  </td>
                  <td data-col="dns">
                    <Show when={item.dns} fallback={<span class="muted">–</span>}>
                      {(dns) => (
                        <span class="dnschg">
                          <DnsName name={dns().name} />
                          <Show when={dns().old}>{(old) => <Addr value={old()} />}</Show>
                          <Icon name="arrow-r" size="xs" />
                          <Addr value={dns().new ?? item.new_ip} />
                        </span>
                      )}
                    </Show>
                  </td>
                  <Show when={preview()}>
                    {(p) => <L2Cell item={item} preview={p()} legacy={l2Step(item) ? stepText(l2Step(item)!, item, p()) : ""} />}
                  </Show>
                  <TimingCell item={item} />
                  <td data-col="manual">
                    <span class="mt">{t("move.tasks", { count: manualCount(item) })}</span>
                  </td>
                </tr>
                <Show when={reasonText(item)}>
                  <tr class="note">
                    <td />
                    <td colSpan={7}>
                      <div class="nt">{reasonText(item)}</div>
                    </td>
                  </tr>
                </Show>
                {/* A refusal of a guardrail is in the network column of its row and in the warnings above. */}
                <For each={(item.warnings ?? []).filter((w) => w.code !== L2_REFUSED_WARNING)}>
                  {(w) => (
                    <tr class="note warn">
                      <td />
                      <td colSpan={7}>
                        <div class="nt">
                          <Icon name="alert" size="xs" /> {warningText(w)}
                        </div>
                      </td>
                    </tr>
                  )}
                </For>
                <Show when={isOpen(item)}>
                  <tr class="sd">
                    <td />
                    <td colSpan={7}>
                      <ol class="steps" data-testid="move-steps">
                        <For each={item.steps}>
                          {(s) => (
                            <li
                              classList={{ auto: s.automatic, manual: !s.automatic }}
                              data-kind={s.kind}
                              data-testid="move-step"
                              data-key={s.kind}
                            >
                              <span class="who">{s.automatic ? t("move.legend.auto") : t("move.legend.manual")}</span>
                              {preview() ? stepText(s, item, preview()!) : ""}
                            </li>
                          )}
                        </For>
                      </ol>
                      <LeaseDetail item={item} />
                      <Show when={preview()}>{(p) => <L2Details item={item} preview={p()} />}</Show>
                    </td>
                  </tr>
                </Show>
              </tbody>
            )}
          </For>
        </table>
        <Show when={loading() && !preview()}>
          <p class="muted" role="status">
            {t("ipam.plan.previewing")}
          </p>
        </Show>

        <Show when={checklist().length > 0}>
          <details class="pv-manual" open data-testid="move-checklist">
            <summary>
              <strong>{t("move.checklist")}</strong>
              <span class="muted"> {t("move.checklist_sum", { count: checklist().reduce((n, g) => n + g.tasks.length, 0) })}</span>
              <span class="tk-aff">
                <button type="button" class="btn sm" disabled title={t("move.tickets_hint")}>
                  {t("move.tickets")}
                </button>
              </span>
            </summary>
            <For each={checklist()}>
              {(group) => (
                <section class="tgroup" data-kind={group.kind} data-testid="move-checklist-group" data-key={group.kind}>
                  <h3>{groupTitle(group.kind, group.tasks.length)}</h3>
                  <ul>
                    <For each={group.tasks}>
                      {(task) => (
                        <li data-testid="move-task">
                          <span class="nm">{deviceName(task.item)}</span> {task.text}
                        </li>
                      )}
                    </For>
                  </ul>
                </section>
              )}
            </For>
            <p class="pv-foot">{t("move.checklist_foot")}</p>
          </details>
        </Show>
      </div>

      <div class="confirm" role="region" aria-label={t("move.confirm")}>
        <div class="cf-row">
          <div class="field">
            <span class="label" id="par-l">
              {t("move.parallelism")}
            </span>
            <div class="cf-inline">
              <Segmented
                label={t("move.parallelism")}
                value={parallelism()}
                options={PARALLELISM.map((p) => ({ value: p, label: p }))}
                onChange={setParallelism}
              />
              <span class="help">{t("move.parallelism_help")}</span>
            </div>
          </div>
          <div class="field">
            <span class="label">{t("move.now_label")}</span>
            <div class="cf-inline">
              <Switch id="move-now" label={t("move.now")} checked={moveNow()} onChange={setMoveNow} />
              <span class="help" data-testid="move-now-help">
                {t("move.now_help")}
              </span>
            </div>
          </div>
          <Show when={preview()?.nudge_offered}>
            <div class="field">
              <span class="label">{t("move.nudge_label")}</span>
              <div class="cf-inline">
                <Switch id="move-nudge" label={t("move.nudge")} checked={nudge()} onChange={setNudge} />
                <span class="help" data-testid="move-nudge-help">
                  {t("move.nudge_help")}
                </span>
              </div>
            </div>
          </Show>
          <div class="field">
            <label for="move-timeout">{t("move.timeout")}</label>
            <div class="cf-inline">
              <select
                id="move-timeout"
                class="select"
                data-testid="move-timeout"
                value={timeout() === null ? "auto" : String(timeout())}
                onChange={(e) => setTimeout_(e.currentTarget.value === "auto" ? null : Number(e.currentTarget.value))}
              >
                <option value="auto">
                  {t("move.timeout_auto", { timeout: preview() && timeout() === null ? formatDuration(preview()!.timeout_secs) : "–" })}
                </option>
                <For each={TIMEOUTS}>{(s) => <option value={String(s)}>{formatDuration(s)}</option>}</For>
              </select>
              <Show when={preview()}>
                {(p) => (
                  <span class="help" data-testid="move-timeout-help">
                    {timeoutText(p().timeout_source, p().timeout_secs, p().target.lease_secs)}
                  </span>
                )}
              </Show>
            </div>
          </div>
          <div class="cf-act">
            <span class="cf-rb">{t("move.rollback_note")}</span>
            <button type="button" class="btn" data-testid="move-cancel" onClick={() => navigate(-1)}>
              {t("common.action.cancel")}
            </button>
            <Show when={mayApply()}>
              <button type="button" class="btn primary" data-testid="move-start" disabled={!canStart()} onClick={() => void start()}>
                {t("move.start", { count: included().length })}
                <Kbd keys={["Ctrl", "Enter"]} />
              </button>
            </Show>
          </div>
        </div>
      </div>
    </div>
  );
}
