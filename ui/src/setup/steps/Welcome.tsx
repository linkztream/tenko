import { For, Show } from "solid-js";
import { Addr } from "../../components/Addr";
import { toast } from "../../components/toast";
import { t, tx } from "../../i18n";
import { formatMemory } from "../format";
import { FOCUS, STEP_COUNT } from "../gates";
import { ProblemNotice } from "../parts";
import { useWizard } from "../controller";

/** Step 1: what Tenko found on this node, and the setup token. */
export function Welcome() {
  const w = useWizard();
  const node = () => w.node();

  const restore = () =>
    toast({ title: t("setup.welcome.restore_title"), body: t("setup.welcome.restore_body"), kind: "info" });

  return (
    <div>
      <p class="wz-lede">{t("setup.welcome.lede", { count: STEP_COUNT })}</p>
      <ProblemNotice step={0} />

      <div class="wz-blk">
        <h2>{t("setup.welcome.found")}</h2>
        <Show when={node()} fallback={<p class="wz-help">{t("setup.welcome.found_none")}</p>}>
          {(n) => (
            <dl class="kv wz-facts">
              <dt>{t("setup.welcome.fact.node")}</dt>
              <dd class="mono">{n().name}</dd>
              <Show when={n().os}>
                <dt>{t("setup.welcome.fact.os")}</dt>
                <dd>{n().os}</dd>
              </Show>
              <Show when={n().cores}>
                <dt>{t("setup.welcome.fact.cpu")}</dt>
                <dd>{t("setup.welcome.cores", { count: n().cores ?? 0 })}</dd>
              </Show>
              <Show when={n().memory_bytes}>
                <dt>{t("setup.welcome.fact.memory")}</dt>
                <dd>{formatMemory(n().memory_bytes ?? 0)}</dd>
              </Show>
              <Show when={(n().addresses ?? []).length > 0}>
                <dt>{t("setup.welcome.fact.address", { count: n().addresses?.length ?? 0 })}</dt>
                <dd>
                  <For each={n().addresses}>
                    {(a, i) => (
                      <>
                        <Show when={i() > 0}>{", "}</Show>
                        <Addr value={a} />
                      </>
                    )}
                  </For>
                </dd>
              </Show>
            </dl>
          )}
        </Show>
      </div>

      <div class="wz-blk">
        <h2>{t("setup.welcome.handy")}</h2>
        <ul class="wz-list">
          <li>{t("setup.welcome.handy.passkey")}</li>
          <li>{t("setup.welcome.handy.host")}</li>
          <li>{t("setup.welcome.handy.disk")}</li>
        </ul>
      </div>

      <div class="wz-blk">
        <h2>{t("setup.welcome.token.title")}</h2>
        <div class="field wz-token">
          <label for={FOCUS.token}>{t("setup.welcome.token.label")}</label>
          <input
            id={FOCUS.token}
            class="input mono"
            value={w.state.token}
            onInput={(e) => w.setState("token", e.currentTarget.value)}
            autocomplete="off"
            autocapitalize="off"
            spellcheck={false}
            aria-required="true"
            aria-describedby="wz-token-help"
          />
          <span class="help" id="wz-token-help">
            {t("setup.welcome.token.help")}
          </span>
        </div>
      </div>

      <p class="wz-help far">
        {tx("setup.welcome.restore", {
          link: (
            <button type="button" class="linkbtn" onClick={restore}>
              {t("setup.welcome.restore_link")}
            </button>
          ),
        })}
      </p>
    </div>
  );
}
