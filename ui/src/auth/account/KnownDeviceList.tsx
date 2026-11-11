import { For, Show } from "solid-js";
import type { KnownDeviceInfo } from "../../api/types";
import { formatDateTime, formatRelative, t } from "../../i18n";

/**
 * The known devices of an account, newest sign-in first. A device is described by dates only;
 * the badge marks the browser that is looking at the page, and the administrator's list has none.
 */
export function KnownDeviceList(props: {
  devices: readonly KnownDeviceInfo[];
  caption: string;
  onForget: (device: KnownDeviceInfo) => void;
}) {
  return (
    <div class="table-wrap">
      <table class="plain" data-testid="known-devices">
        <caption class="sr-only">{props.caption}</caption>
        <thead>
          <tr>
            <th scope="col">{t("account.devices.col.last_sign_in")}</th>
            <th scope="col">{t("account.devices.col.known_since")}</th>
            <th scope="col">{t("account.devices.col.until")}</th>
            <th scope="col" class="r">
              <span class="sr-only">{t("account.devices.col.actions")}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <For each={props.devices}>
            {(d) => (
              <tr>
                <td class="num" title={formatDateTime(d.last_sign_in)}>
                  {formatRelative(d.last_sign_in)}
                  <span class="muted"> ({formatDateTime(d.last_sign_in)})</span>
                  <Show when={d.current}>
                    <span class="tag accent acct-this">{t("account.devices.this")}</span>
                  </Show>
                </td>
                <td class="num">{formatDateTime(d.known_since)}</td>
                <td class="num">{formatDateTime(d.expires_at)}</td>
                <td class="r">
                  <button
                    type="button"
                    class="btn sm"
                    aria-label={t("account.devices.forget_named", { when: formatDateTime(d.last_sign_in) })}
                    onClick={() => props.onForget(d)}
                  >
                    {t("account.devices.forget")}
                  </button>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}
