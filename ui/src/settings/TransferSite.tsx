// The networks that count as "the site" for zone transfers: under the Hardened profile a
// transfer to an address outside them must come over TLS (XoT). One network per line.
import { createEffect, createMemo, createSignal, on, Show, untrack } from "solid-js";
import type { SecuritySettingsView, SettingsPatch } from "../api/types";
import { parseCidr } from "../ipam/ip";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { FieldHelp, fieldRefusal, ReloadedNote } from "./fields";

/** The ranges that count as the site when the settings do not say (the server's default). */
export const TRANSFER_SITE_DEFAULT: readonly string[] = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "fc00::/7",
  "::1/128",
  "fe80::/10",
];

/** The networks of the settings; settings that do not say follow the default. */
export function transferSiteOf(view: SecuritySettingsView): string[] {
  return [...(view.settings.transfer_site ?? TRANSFER_SITE_DEFAULT)];
}

/** The networks of a text, one per line, blank lines left out. */
export function parseTransferSite(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

/** Whether a line looks like a CIDR network: an address, a slash and a prefix length within range. */
function looksLikeNetwork(line: string): boolean {
  return line.includes("/") && parseCidr(line, { strict: false }) !== null;
}

const toText = (list: readonly string[]) => list.join("\n");

export function TransferSite(props: {
  view: SecuritySettingsView;
  save: (patch: SettingsPatch) => Promise<SecuritySettingsView>;
}) {
  const [text, setText] = createSignal(toText(untrack(() => transferSiteOf(props.view))));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  // A reload or a profile switch brings a new list.
  // The stored list as text; a memo, so that saving another setting (a new view with the
  // same list) does not overwrite what is being edited here.
  const stored = createMemo(() => toText(transferSiteOf(props.view)));
  createEffect(on(stored, (value) => setText(value), { defer: true }));

  const lines = () => parseTransferSite(text());
  const bad = () => lines().find((line) => !looksLikeNetwork(line));
  const changed = () => toText(lines()) !== toText(transferSiteOf(props.view));
  const refusal = () => fieldRefusal(error(), "transfer_site");

  const submit = async (e: Event) => {
    e.preventDefault();
    if (bad() !== undefined || !changed() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const next = await props.save({ transfer_site: lines() });
      setText(toText(transferSiteOf(next)));
      toast({ kind: "ok", title: t("settings.security.transfer_site.saved") });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page-section" aria-labelledby="sec-transfer-site" data-testid="transfer-site">
      <h2 id="sec-transfer-site">{t("settings.security.transfer_site.heading")}</h2>
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <ErrorNotice error={refusal() === undefined ? error() : null} />
        <ReloadedNote error={error()} />
        <div class="field">
          <label for="tg-transfer-site">{t("settings.security.transfer_site.label")}</label>
          <textarea
            id="tg-transfer-site"
            data-testid="field-transfer_site"
            class="input mono"
            rows={9}
            spellcheck={false}
            autocomplete="off"
            value={text()}
            aria-invalid={bad() !== undefined || refusal() !== undefined ? "true" : undefined}
            aria-describedby="tg-transfer-site-help"
            onInput={(e) => setText(e.currentTarget.value)}
          />
          <FieldHelp
            id="tg-transfer-site-help"
            help={t("settings.security.transfer_site.help")}
            error={
              bad() !== undefined
                ? t("settings.security.transfer_site.error", { line: bad() ?? "" })
                : refusal()
            }
          />
        </div>
        <div class="form-row">
          <button type="submit" class="btn" disabled={busy() || bad() !== undefined || !changed()} data-testid="transfer-site-save">
            {t("settings.security.save")}
          </button>
          <Show when={text() !== toText(TRANSFER_SITE_DEFAULT)}>
            <button
              type="button"
              class="btn ghost"
              data-testid="transfer-site-default"
              onClick={() => setText(toText(TRANSFER_SITE_DEFAULT))}
            >
              {t("settings.security.transfer_site.use_default")}
            </button>
          </Show>
        </div>
      </form>
    </section>
  );
}
