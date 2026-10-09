import { Show } from "solid-js";
import type { DataDirFacts } from "../../api/types";
import { Icon } from "../../components/Icon";
import { t, tx } from "../../i18n";
import { formatDiskSize, formatMicros } from "../format";
import { FOCUS } from "../gates";
import { ProblemNotice } from "../parts";
import { useWizard } from "../controller";

/** How a node is moved to another disk: restart it with another data directory. */
const MOVE_COMMAND = "tenko serve --data-dir";

const MEDIA = {
  nvme: "setup.disk.media.nvme",
  ssd: "setup.disk.media.ssd",
  hdd: "setup.disk.media.hdd",
  smr: "setup.disk.media.smr",
  unknown: "setup.disk.media.unknown",
} as const satisfies Record<DataDirFacts["media"], string>;

/** Step 5: the data directory the node already uses, and whether its disk is fit for it. */
export function DataDir() {
  const w = useWizard();

  return (
    <div>
      <p class="wz-lede">{t("setup.disk.lede")}</p>
      <ProblemNotice step={4} />

      <div class="wz-blk tight">
        <h2>{t("setup.disk.detected")}</h2>
        <Show when={w.dataDir()} fallback={<p class="wz-help">{t("setup.disk.unknown")}</p>}>
          {(d) => (
            <>
              <div class="wz-choice static" classList={{ risk: w.disk() !== null }}>
                <Icon name="disk" class="disk-icon" />
                <span>
                  <span class="t">
                    <span class="mono">{d().path}</span>
                    <Show when={d().device}>
                      <span class="on">{t("setup.disk.on")}</span>
                      <span class="mono">{d().device}</span>
                    </Show>
                  </span>
                  <span class="d">
                    {d().free_bytes != null
                      ? t("setup.disk.media_free", { media: t(MEDIA[d().media]), size: formatDiskSize(d().free_bytes ?? 0) })
                      : t(MEDIA[d().media])}
                  </span>
                  <Show when={d().fsync_p50_micros != null}>
                    <span class="d">{t("setup.disk.fsync", { time: formatMicros(d().fsync_p50_micros ?? 0) })}</span>
                  </Show>
                </span>
                <Show
                  when={w.disk()}
                  fallback={<span class="tag accent">{t("common.recommended")}</span>}
                >
                  {(risk) => (
                    <span class="tag discrepancy">
                      <Icon name="alert" size="xs" />
                      {risk() === "rotating" ? t("setup.disk.tag.rotating") : t("setup.disk.tag.slow")}
                    </span>
                  )}
                </Show>
              </div>

              <Show when={w.disk()}>
                {(risk) => (
                  <div class="note warn wz-note" role="alert">
                    <Icon name="alert" size="sm" />
                    <div class="grow">
                      <strong>{risk() === "rotating" ? t("setup.disk.warn.rotating_title") : t("setup.disk.warn.slow_title")}</strong>{" "}
                      {risk() === "rotating" ? t("setup.disk.warn.rotating_body") : t("setup.disk.warn.slow_body")}
                      <p class="wz-help gap">
                        {tx("setup.disk.move", {
                          command: <span class="mono">{`${MOVE_COMMAND} <${t("setup.disk.move_path")}>`}</span>,
                        })}
                      </p>
                      <label class="wz-override">
                        <input
                          id={FOCUS.diskOverride}
                          class="cb"
                          type="checkbox"
                          checked={w.state.acceptSlowDisk}
                          onChange={(e) => w.setState("acceptSlowDisk", e.currentTarget.checked)}
                        />
                        {t("setup.disk.override")}
                      </label>
                    </div>
                  </div>
                )}
              </Show>
            </>
          )}
        </Show>
      </div>

      <div class="wz-blk">
        <h2>
          {t("setup.disk.contents")}
          <Show when={w.dataDir()?.free_bytes != null}>
            <span class="aside">{t("setup.disk.free_aside", { size: formatDiskSize(w.dataDir()?.free_bytes ?? 0) })}</span>
          </Show>
        </h2>
        <table class="wz-tg" aria-label={t("setup.disk.table.label")}>
          <thead>
            <tr>
              <th scope="col">{t("setup.disk.table.item")}</th>
              <th scope="col">{t("setup.disk.table.contains")}</th>
              <th scope="col" class="r">
                {t("setup.disk.table.size")}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td class="k narrow">{t("setup.disk.item.store")}</td>
              <td class="v">{t("setup.disk.item.store_contains")}</td>
              <td class="sz">{t("setup.disk.item.store_size")}</td>
            </tr>
            <tr>
              <td class="k narrow">{t("setup.disk.item.leases")}</td>
              <td class="v">{t("setup.disk.item.leases_contains")}</td>
              <td class="sz">{t("setup.disk.item.leases_size")}</td>
            </tr>
            <tr>
              <td class="k narrow">{t("setup.disk.item.keys")}</td>
              <td class="v">{t("setup.disk.item.keys_contains")}</td>
              <td class="sz">{t("setup.disk.item.keys_size")}</td>
            </tr>
            <tr>
              <td class="k narrow">{t("setup.disk.item.audit")}</td>
              <td class="v">{t("setup.disk.item.audit_contains")}</td>
              <td class="sz">{t("setup.disk.item.audit_size")}</td>
            </tr>
          </tbody>
          <tfoot>
            <tr>
              <td colspan="2">{t("setup.disk.total_note")}</td>
              <td class="sz">
                <strong>{t("setup.disk.total_size")}</strong>
              </td>
            </tr>
          </tfoot>
        </table>
      </div>
    </div>
  );
}
