// The infrastructure cache section of the DNS settings page (WP10.4), beside the cache section:
// what the recursive resolver knows about the authorities, as `unbound-control dump_infra` and
// BIND's ADB dump show it. A page per zone cut: the zone, whether its delegation is signed, the
// time the cut stays, and per server and address where the address came from, its smoothed
// round-trip time and percentiles, its failures and what it can do (EDNS, TCP only, lower case
// only, lame, down). A suffix narrows the listing to a zone and the zones under it. The cache
// holds no client data, so nothing is audited by reading it; it is still read only when asked.
// "Flush" empties the cuts at or below the suffix, or everything (the root is primed again),
// after a confirmation; the flush is audited. A node whose resolver is off answers 409
// `dns.recursion.disabled`, which is shown as a notice.
import { createResource, createSignal, For, Show } from "solid-js";
import { ApiError, errorMessage } from "../../api/problem";
import { ConfirmDialog } from "../../components/Dialog";
import { ErrorNotice, Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatNumber, t } from "../../i18n";
import { cacheSuffix, ttlLeft } from "../../dns/cache/model";
import { addressesOf, capabilities, flushInfra, listInfra, type InfraCut } from "./infra";

/** The node's resolver is off. */
function recursionOff(err: unknown): boolean {
  return err instanceof ApiError && err.code === "dns.recursion.disabled";
}

const DS_STATES = ["secure", "insecure", "bogus"] as const;
const ORIGINS = ["hints", "glue", "sibling_glue", "authoritative"] as const;

/** The words of a cut's DS state; a state this version does not know reads as not known. */
function dsText(ds: string): string {
  const known = DS_STATES.find((state) => state === ds);
  return known ? t(`dns.infra.ds.${known}`) : t("dns.infra.ds.unknown");
}

/** Where an address was learned; an origin this version does not know is shown as written. */
function originText(origin: string): string {
  const known = ORIGINS.find((word) => word === origin);
  return known ? t(`dns.infra.origin.${known}`) : origin;
}

function ms(value: number | null | undefined): string {
  return value == null ? "" : t("dns.infra.ms", { ms: formatNumber(value, { maximumFractionDigits: 1 }) });
}

function Ttl(props: { seconds: number }) {
  const left = () => ttlLeft(props.seconds);
  return <>{t(`dns.cache.ttl_${left().unit}`, { value: formatNumber(left().value) })}</>;
}

function Cut(props: { cut: InfraCut; index: number }) {
  const rows = () => addressesOf(props.cut);
  return (
    <section class="card dns-infra-cut" data-testid="dns-infra-cut" data-index={props.index} data-key={props.cut.zone} data-ds={props.cut.ds}>
      <h3 class="dns-infra-zone">
        <span class="mono">{props.cut.zone}</span>
        <span class="tag" classList={{ discrepancy: props.cut.ds === "bogus" }} data-testid="dns-infra-ds">
          {dsText(props.cut.ds)}
        </span>
        <span class="muted">
          <Ttl seconds={props.cut.ttl} />
        </span>
      </h3>
      <Show when={rows().length > 0} fallback={<p class="muted">{t("dns.infra.no_addresses", { servers: props.cut.servers.length })}</p>}>
        <div class="table-wrap">
          <table class="plain dns-infra-table">
            <caption class="sr-only">{t("dns.infra.servers_of", { zone: props.cut.zone })}</caption>
            <thead>
              <tr>
                <th scope="col">{t("dns.infra.col.server")}</th>
                <th scope="col">{t("dns.infra.col.address")}</th>
                <th scope="col">{t("dns.infra.col.origin")}</th>
                <th scope="col" class="r">
                  {t("dns.infra.col.srtt")}
                </th>
                <th scope="col" class="r">
                  {t("dns.infra.col.p99")}
                </th>
                <th scope="col" class="r">
                  {t("dns.infra.col.failures")}
                </th>
                <th scope="col">{t("dns.infra.col.capabilities")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={rows()}>
                {(row) => (
                  <tr data-testid="dns-infra-address" data-key={row.address.address} data-server={row.server}>
                    <td class="mono">{row.server}</td>
                    <td class="mono">{row.address.address}</td>
                    <td>{originText(row.address.origin)}</td>
                    <td class="r nowrap" data-col="srtt">
                      <Show when={row.address.srtt_ms != null} fallback={<span class="muted">{t("dns.infra.srtt_none")}</span>}>
                        {ms(row.address.srtt_ms)}
                      </Show>
                    </td>
                    <td class="r nowrap">{ms(row.address.p99_ms)}</td>
                    <td class="r">{formatNumber(row.address.failures)}</td>
                    <td>
                      <span class="dns-chips">
                        <For each={capabilities(row.address)}>
                          {(cap) => (
                            <span class="tag" classList={{ discrepancy: cap === "lame" || cap === "down" }} data-testid="dns-infra-capability" data-key={cap}>
                              {t(`dns.infra.capability.${cap}`)}
                            </span>
                          )}
                        </For>
                      </span>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </section>
  );
}

export function InfraSection(props: { node: number }) {
  const [typed, setTyped] = createSignal("");
  const [invalid, setInvalid] = createSignal(false);
  // The suffix of the pages shown and the cursors from the first page to the one shown;
  // undefined until the administrator asks.
  const [shown, setShown] = createSignal<{ suffix: string; cursors: (string | undefined)[]; tick: number }>();
  const [confirming, setConfirming] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const request = () => {
    const current = shown();
    if (!current) return undefined;
    return { suffix: current.suffix, cursor: current.cursors[current.cursors.length - 1], tick: current.tick };
  };
  const [page] = createResource(request, (r) => listInfra(props.node, r.suffix, r.cursor));

  const typedSuffix = () => cacheSuffix(typed());
  const show = (event: Event) => {
    event.preventDefault();
    const suffix = typedSuffix();
    setInvalid(suffix === null);
    if (suffix === null) return;
    setShown({ suffix, cursors: [undefined], tick: (shown()?.tick ?? 0) + 1 });
  };
  const move = (cursors: (string | undefined)[]) => {
    const current = shown();
    if (current) setShown({ ...current, cursors });
  };
  const next = () => {
    const cursor = page.latest?.next;
    const current = shown();
    if (cursor && current) move([...current.cursors, cursor]);
  };
  const previous = () => move(shown()?.cursors.slice(0, -1) ?? [undefined]);
  const askFlush = () => {
    const suffix = typedSuffix();
    setInvalid(suffix === null);
    if (suffix !== null) setConfirming(suffix);
  };

  const flush = async (suffix: string) => {
    if (busy()) return;
    setBusy(true);
    try {
      const entries = await flushInfra(props.node, suffix);
      toast({ kind: "ok", title: suffix ? t("dns.infra.flushed_suffix", { suffix, entries }) : t("dns.infra.flushed_all", { entries }) });
      setConfirming(null);
      const current = shown();
      if (current) setShown({ ...current, cursors: [undefined], tick: current.tick + 1 });
    } catch (err) {
      toast({ kind: "bad", title: t("dns.infra.flush_failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page-section dns-set-group" data-testid="dns-infra">
      <h2>{t("dns.infra.title")}</h2>
      <p class="muted dns-set-doc">{t("dns.infra.lede")}</p>
      <form class="dns-cache-form" data-testid="dns-infra-form" onSubmit={show} novalidate>
        <div class="field">
          <label for="dns-infra-suffix">{t("dns.infra.suffix")}</label>
          <input
            id="dns-infra-suffix"
            class="input mono"
            value={typed()}
            placeholder={t("dns.cache.suffix_placeholder")}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={invalid() ? "true" : undefined}
            data-testid="field-infra-suffix"
            onInput={(event) => setTyped(event.currentTarget.value)}
          />
          <Show when={invalid()}>
            <span class="help bad" data-testid="field-error" data-field="infra-suffix">
              {t("dns.cache.suffix_invalid")}
            </span>
          </Show>
        </div>
        <div class="dns-cache-actions">
          <button type="submit" class="btn primary" data-testid="dns-infra-show">
            {shown() ? t("dns.cache.reload") : t("dns.infra.show")}
          </button>
          <button type="button" class="btn" data-testid="dns-infra-flush" disabled={busy()} onClick={askFlush}>
            {typedSuffix() ? t("dns.infra.flush_suffix", { suffix: typedSuffix() ?? "" }) : t("dns.infra.flush_all")}
          </button>
        </div>
      </form>
      <Show when={page.error}>
        <Show when={recursionOff(page.error)} fallback={<ErrorNotice error={page.error} />}>
          <Notice kind="info" role="status" testid="dns-infra-off">
            {t("dns.infra.off")}
          </Notice>
        </Show>
      </Show>
      <Show when={shown() && !page.error && page.latest}>
        {(current) => (
          <>
            <Show
              when={current().items.length > 0}
              fallback={
                <div class="empty" data-testid="dns-infra-empty">
                  <h3>{shown()?.suffix ? t("dns.infra.empty_suffix", { suffix: shown()?.suffix ?? "" }) : t("dns.infra.empty")}</h3>
                </div>
              }
            >
              <div class="dns-infra-cuts" data-testid="dns-infra-cuts">
                <For each={current().items}>{(cut, index) => <Cut cut={cut} index={index()} />}</For>
              </div>
            </Show>
            <div class="dns-cache-paging" data-testid="dns-infra-paging" data-page={shown()?.cursors.length}>
              <button type="button" class="btn" data-testid="dns-infra-previous" disabled={(shown()?.cursors.length ?? 1) <= 1 || page.loading} onClick={previous}>
                {t("dns.cache.previous")}
              </button>
              <span class="muted">{t("dns.cache.page", { page: shown()?.cursors.length ?? 1 })}</span>
              <button type="button" class="btn" data-testid="dns-infra-next" disabled={!current().next || page.loading} onClick={next}>
                {t("dns.cache.next")}
              </button>
            </div>
          </>
        )}
      </Show>
      <Show when={confirming() !== null}>
        <ConfirmDialog
          testid="dns-infra-flush-dialog"
          title={confirming() ? t("dns.infra.flush_title_suffix", { suffix: confirming() ?? "" }) : t("dns.infra.flush_title_all")}
          body={<p>{confirming() ? t("dns.infra.flush_body_suffix", { suffix: confirming() ?? "" }) : t("dns.infra.flush_body_all")}</p>}
          confirmLabel={t("dns.infra.flush_confirm")}
          cancelLabel={t("dns.cache.flush_cancel")}
          danger
          busy={busy()}
          onConfirm={() => void flush(confirming() ?? "")}
          onClose={() => setConfirming(null)}
        />
      </Show>
    </section>
  );
}
