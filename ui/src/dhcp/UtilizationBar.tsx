// How full a scope is, as a bar and the percent (the scope list, WP7.4) and, with `detail`, the
// figures behind it and the time they were read (the live strip of the lease list, WP8.6). The
// figures are read when the bar appears and again whenever `revision` changes.
import { createEffect, createResource, Show } from "solid-js";
import { formatDateTime, formatNumber, t } from "../i18n";
import { getUtilization } from "./api";
import { percentOf } from "./model";

const READ_AT: Intl.DateTimeFormatOptions = { timeStyle: "medium" };

export function UtilizationBar(props: {
  prefix: string;
  revision?: number | undefined;
  /** Shows the pool size, the leased, reserved, abandoned and free addresses and when they were read. */
  detail?: boolean | undefined;
  /** Told the percentage every time it was read. */
  onRead?: ((percent: number) => void) | undefined;
}) {
  const [util] = createResource(
    () => [props.prefix, props.revision] as const,
    ([prefix]) => getUtilization(prefix),
  );
  const shown = () => (util.error ? undefined : util.latest);
  createEffect(() => {
    const u = shown();
    if (u) props.onRead?.(percentOf(u.utilization));
  });
  return (
    <Show when={shown()} fallback={<span class="muted">{util.error ? "" : "…"}</span>}>
      {(u) => {
        const pct = () => percentOf(u().utilization);
        return (
          <>
            <span class="dhcp-util" data-testid="scope-util" data-key={String(pct())}>
              <span class="dhcp-bar" role="img" aria-label={t("dhcp.util.label", { percent: pct() })}>
                <span style={{ width: `${pct()}%` }} classList={{ warn: pct() >= 70 && pct() < 90, crit: pct() >= 90 }} />
              </span>
              <span class="num">{formatNumber(pct() / 100, { style: "percent" })}</span>
            </span>
            <Show when={props.detail}>
              <span class="dhcp-util-facts" data-testid="util-facts">
                <span class="dhcp-fact" data-testid="util-fact" data-key="leased">
                  {t("dhcp.util.leased")} <b>{formatNumber(u().leased)}</b>
                </span>
                <span class="dhcp-fact" data-testid="util-fact" data-key="reserved">
                  {t("dhcp.util.reserved")} <b>{formatNumber(u().reserved)}</b>
                </span>
                <span class="dhcp-fact" data-testid="util-fact" data-key="abandoned">
                  {t("dhcp.util.abandoned")} <b>{formatNumber(u().abandoned)}</b>
                </span>
                <span class="dhcp-fact" data-testid="util-fact" data-key="free">
                  {t("dhcp.util.free")} <b>{formatNumber(u().free)}</b>
                </span>
                <span class="dhcp-fact" data-testid="util-fact" data-key="pool_size">
                  {t("dhcp.util.pool_size")} <b>{formatNumber(u().pool_size)}</b>
                </span>
                <span class="dhcp-fact muted" data-testid="util-at">
                  {t("dhcp.util.at", { time: formatDateTime(u().at, READ_AT) })}
                </span>
              </span>
            </Show>
          </>
        );
      }}
    </Show>
  );
}
