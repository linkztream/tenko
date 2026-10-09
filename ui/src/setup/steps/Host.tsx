import { For, Show } from "solid-js";
import type { TlsMode } from "../../api/types";
import { Icon } from "../../components/Icon";
import { formatList, t } from "../../i18n";
import { FOCUS } from "../gates";
import { ProblemNotice } from "../parts";
import { parseProxyList, validateHostName, type HostNameProblem } from "../validate";
import { useWizard } from "../controller";

const MODES: readonly TlsMode[] = ["internal_ca", "imported", "reverse_proxy", "plain"];

const NAME = {
  internal_ca: "setup.tls.internal_ca.name",
  imported: "setup.tls.imported.name",
  reverse_proxy: "setup.tls.reverse_proxy.name",
  plain: "setup.tls.plain.name",
} as const satisfies Record<TlsMode, string>;

const DESCRIPTION = {
  internal_ca: "setup.tls.internal_ca.description",
  imported: "setup.tls.imported.description",
  reverse_proxy: "setup.tls.reverse_proxy.description",
  plain: "setup.tls.plain.description",
} as const satisfies Record<TlsMode, string>;

const PROBLEM = {
  empty: "setup.host.error.empty",
  address: "setup.host.error.address",
  chars: "setup.host.error.chars",
  length: "setup.host.error.length",
} as const satisfies Record<HostNameProblem, string>;

/** Step 4: the host name (certificate name and passkey relying party) and how TLS is done. */
export function Host() {
  const w = useWizard();
  const check = () => validateHostName(w.state.hostName);
  const problem = () => {
    const c = check();
    return w.state.hostName.trim() !== "" && !c.ok ? c.problem : null;
  };
  const helpText = (): string => {
    const p = problem();
    return p === null ? t("setup.host.help") : t(PROBLEM[p]);
  };
  const proxies = () => parseProxyList(w.state.proxies);
  const proxyProblem = () => w.state.tlsMode === "reverse_proxy" && proxies().invalid.length > 0;
  const lab = () => w.state.profile === "lab";

  return (
    <div>
      <p class="wz-lede">{t("setup.host.lede")}</p>
      <ProblemNotice step={3} />

      <div class="wz-blk tight">
        <div class="field wz-host">
          <label for={FOCUS.hostName}>{t("setup.host.label")}</label>
          <input
            id={FOCUS.hostName}
            data-testid="field-host-name"
            class="input mono"
            classList={{ bad: problem() !== null }}
            value={w.state.hostName}
            placeholder={t("setup.host.placeholder", { name: w.node()?.name ?? "tenko" })}
            onInput={(e) => w.setState("hostName", e.currentTarget.value)}
            autocomplete="off"
            autocapitalize="off"
            spellcheck={false}
            aria-required="true"
            aria-invalid={problem() !== null ? "true" : undefined}
            aria-describedby="wz-host-help"
          />
          <span class="help" classList={{ bad: problem() !== null }} id="wz-host-help">
            {helpText()}
          </span>
        </div>
      </div>

      <div class="wz-blk">
        <h2 id="wz-tls-title">{t("setup.tls.title")}</h2>
        <div role="radiogroup" aria-labelledby="wz-tls-title">
          <For each={MODES}>
            {(mode) => {
              const disabled = () => mode === "plain" && !lab();
              return (
                <label class="wz-choice">
                  <input
                    id={mode === "plain" ? FOCUS.tlsPlain : undefined}
                    class="wz-rd"
                    type="radio"
                    name="wz-tls"
                    data-testid="setup-tls"
                    data-key={mode}
                    value={mode}
                    checked={w.state.tlsMode === mode}
                    disabled={disabled()}
                    onChange={() => w.setState("tlsMode", mode)}
                  />
                  <span>
                    <span class="t">
                      {t(NAME[mode])}
                      <Show when={mode === "internal_ca"}>
                        <span class="tag accent">{t("setup.tls.default")}</span>
                      </Show>
                    </span>
                    <span class="d">{disabled() ? t("setup.tls.plain.disabled") : t(DESCRIPTION[mode])}</span>
                  </span>
                  <span />
                </label>
              );
            }}
          </For>
        </div>

        <Show when={w.state.tlsMode === "reverse_proxy"}>
          <div class="field wz-proxies">
            <label for={FOCUS.proxies}>{t("setup.tls.proxies.label")}</label>
            <textarea
              id={FOCUS.proxies}
              class="input mono"
              classList={{ bad: proxyProblem() }}
              rows={3}
              value={w.state.proxies}
              onInput={(e) => w.setState("proxies", e.currentTarget.value)}
              autocomplete="off"
              spellcheck={false}
              aria-required="true"
              aria-invalid={proxyProblem() ? "true" : undefined}
              aria-describedby="wz-proxies-help"
            />
            <span class="help" classList={{ bad: proxyProblem() }} id="wz-proxies-help">
              {proxyProblem()
                ? t("setup.tls.proxies.invalid", { entries: formatList(proxies().invalid), count: proxies().invalid.length })
                : t("setup.tls.proxies.help")}
            </span>
          </div>
        </Show>
      </div>

      <div class="wz-blk after">
        <div class="note" classList={{ warn: w.state.tlsMode === "plain" }}>
          <Icon name={w.state.tlsMode === "plain" ? "alert" : "lock"} size="sm" />
          <div class="grow">{w.state.tlsMode === "plain" ? t("setup.tls.passkey_note_plain") : t("setup.tls.passkey_note")}</div>
        </div>
      </div>
    </div>
  );
}
