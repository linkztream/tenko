// The move preview (IPAM-19, design decisions 6 to 8): a page of its own, reached by dropping
// hosts or addresses on a network of the tree or with M. Per device it shows the old and the
// new address (the same host part when it is free, else the next free address by the
// network's policy), the DNS change, the network (L2) step and the manual steps; below, one
// grouped checklist of every manual task of the whole batch. Nothing changes until "Start"
// is confirmed: then one job per device starts, all in one group with the chosen
// parallelism, and the page hands over to the jobs list of that group. The observation
// timeout defaults to half the DHCP lease of the target and rolls a device back on expiry.
import { A, useNavigate, useSearchParams } from "@solidjs/router";
import { createEffect, createMemo, createSignal, For, on, onCleanup, onMount, Show } from "solid-js";
import { newIdempotencyKey } from "../../api/client";
import { previewMove, submitMove, type MoveItem, type MovePreview as Preview } from "../../api/moves";
import type { ObjectRef } from "../../api/types";
import { paths } from "../../app/paths";
import { Addr } from "../../components/Addr";
import { Icon } from "../../components/Icon";
import { Kbd } from "../../components/Kbd";
import { ErrorNotice, Notice } from "../../components/Notice";
import { Segmented } from "../../components/Segmented";
import { toast } from "../../components/toast";
import { DnsName, ModeBadge } from "../../grid/cells";
import { formatDuration, t } from "../../i18n";
import { IpamNav } from "../IpamNav";
import { warningText } from "../plan/describe";
import { deviceName, groupTitle, reasonText, STEP_ORDER, stepText, timeoutText } from "./moveText";
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

export default function MovePreview() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const target = () => (typeof params.target === "string" ? params.target : "");
  const requested = createMemo(() => parseObjects(typeof params.objects === "string" ? params.objects : undefined));

  const [excluded, setExcluded] = createSignal<ObjectRef[]>([]);
  const [parallelism, setParallelism] = createSignal<string>("2");
  const [timeout, setTimeout_] = createSignal<number | null>(null);
  const [acked, setAcked] = createSignal<ReadonlySet<string>>(new Set());
  const [preview, setPreview] = createSignal<Preview | null>(null);
  const [error, setError] = createSignal<unknown>(null);
  const [loading, setLoading] = createSignal(false);
  const [starting, setStarting] = createSignal(false);
  const [open, setOpen] = createSignal<ReadonlySet<string>>(new Set());
  const [allOpen, setAllOpen] = createSignal(false);
  let key = newIdempotencyKey();
  let controller: AbortController | undefined;

  const included = createMemo(() => requested().filter((o) => !excluded().some((x) => sameRef(x, o))));

  const request = () => ({
    objects: included(),
    target: target(),
    timeout_secs: timeout(),
    parallelism: Number(parallelism()),
    acknowledge: [...acked()],
  });

  // Every change of the inputs previews again; a new preview means a new confirmation.
  createEffect(
    on(
      () => JSON.stringify(request()),
      async () => {
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
  const l2Step = (item: MoveItem) => item.steps.find((s) => s.kind === "l2.move");
  const blocking = () => (preview()?.unacknowledged ?? []).filter((c) => !acked().has(c));
  const canStart = () => !!preview() && !loading() && !starting() && blocking().length === 0 && included().length > 0;

  const start = async () => {
    if (!canStart()) return;
    setStarting(true);
    setError(null);
    try {
      const result = await submitMove(request(), key);
      const count = result.jobs.length;
      toast({
        kind: "ok",
        title: t("move.started", { count }),
        actions: [{ label: t("move.open_jobs"), run: () => navigate(paths.jobs({ group: result.group })) }],
      });
      navigate(paths.jobs({ group: result.group }), { replace: true });
    } catch (err) {
      setError(err);
      setStarting(false);
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

        <table class="grid grouped pvt" aria-label={t("move.devices")} aria-busy={loading() ? "true" : undefined} data-testid="move-devices">
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
                  <td data-col="l2">{l2Step(item) && preview() ? stepText(l2Step(item)!, item, preview()!) : ""}</td>
                  <td data-col="manual">
                    <span class="mt">{t("move.tasks", { count: manualCount(item) })}</span>
                  </td>
                </tr>
                <Show when={reasonText(item)}>
                  <tr class="note">
                    <td />
                    <td colSpan={6}>
                      <div class="nt">{reasonText(item)}</div>
                    </td>
                  </tr>
                </Show>
                <For each={item.warnings ?? []}>
                  {(w) => (
                    <tr class="note warn">
                      <td />
                      <td colSpan={6}>
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
                    <td colSpan={6}>
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
            <button type="button" class="btn primary" data-testid="move-start" disabled={!canStart()} onClick={() => void start()}>
              {t("move.start", { count: included().length })}
              <Kbd keys={["Ctrl", "Enter"]} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
