import { Show, type JSX } from "solid-js";
import { NODE_ROLES, type TlsMode } from "../../api/types";
import { formatList, t } from "../../i18n";
import { parseProxyList } from "../validate";
import { ProblemNotice } from "../parts";
import { useWizard } from "../controller";

const TLS_NAME = {
  internal_ca: "setup.tls.internal_ca.name",
  imported: "setup.tls.imported.name",
  reverse_proxy: "setup.tls.reverse_proxy.name",
  plain: "setup.tls.plain.name",
} as const satisfies Record<TlsMode, string>;

const ROLE_NAME = {
  controller: "node.role.controller",
  dns: "node.role.dns",
  dhcp: "node.role.dhcp",
  probe: "node.role.probe",
} as const;

function Row(props: { label: string; change?: { step: number; item: string }; children: JSX.Element }) {
  const w = useWizard();
  return (
    <div class="wz-sumrow">
      <dt class="k">{props.label}</dt>
      <dd class="v">{props.children}</dd>
      <dd>
        <Show when={props.change}>
          {(c) => (
            <button type="button" class="linkbtn" onClick={() => w.review(c().step)} aria-label={t("setup.done.change_item", { item: c().item })}>
              {t("setup.done.change")}
            </button>
          )}
        </Show>
      </dd>
    </div>
  );
}

/** Step 7: the choices at a glance, before anything is written. */
export function Review() {
  const w = useWizard();
  const roleNames = () => NODE_ROLES.filter((r) => w.state.roles[r]).map((r) => t(ROLE_NAME[r]));
  const networkNames = () => w.networks().filter((n) => w.state.networks[n.id]).map((n) => n.name);
  return (
    <div>
      <p class="wz-lede">{t("setup.done.lede")}</p>
      <ProblemNotice step={6} />

      <div class="wz-blk tight">
        <h2>{t("setup.done.choices")}</h2>
        <dl class="wz-sum">
          <Row label={t("setup.done.profile")} change={{ step: 1, item: t("setup.done.profile") }}>
            {t(`profile.${w.state.profile}.name`)}
            <Show when={w.state.profile === "lab"}>
              {" "}
              <span class="tag conflict">{t("setup.done.not_production")}</span>
            </Show>
          </Row>
          <Row label={t("setup.done.admin")} change={{ step: 2, item: t("setup.done.admin") }}>
            <span class="mono">{w.state.userName.trim()}</span>, {w.state.displayName.trim()}
          </Row>
          <Row label={t("setup.done.passkey")}>
            <Show
              when={w.state.profile === "hardened"}
              fallback={<span class="muted">{t("setup.done.passkey_optional")}</span>}
            >
              <span class="tag discrepancy">{t("setup.done.passkey_required")}</span>
            </Show>
          </Row>
          <Row label={t("setup.done.host")} change={{ step: 3, item: t("setup.done.host") }}>
            <span class="mono">{w.state.hostName.trim()}</span>
            <div class="wz-help">
              {t(TLS_NAME[w.state.tlsMode])}
              <Show when={w.state.tlsMode === "reverse_proxy"}>
                {` (${t("setup.done.proxies", { count: parseProxyList(w.state.proxies).entries.length })})`}
              </Show>
            </div>
          </Row>
          <Row label={t("setup.done.disk")} change={{ step: 4, item: t("setup.done.disk") }}>
            <Show when={w.dataDir()} fallback={<span class="muted">{t("setup.done.disk_unknown")}</span>}>
              {(d) => (
                <>
                  <span class="mono">{d().path}</span>
                  <Show when={d().device}>
                    {" "}
                    <span class="muted">{t("setup.disk.on")}</span> <span class="mono">{d().device}</span>
                  </Show>
                  <Show when={w.disk() !== null && w.state.acceptSlowDisk}>
                    {" "}
                    <span class="tag discrepancy">{t("setup.done.disk_override")}</span>
                  </Show>
                </>
              )}
            </Show>
          </Row>
          <Row label={t("setup.done.roles")} change={{ step: 5, item: t("setup.done.roles") }}>
            {formatList(roleNames())}
            <Show when={w.state.roles.probe}>
              <div class="wz-help">
                {networkNames().length > 0
                  ? t("setup.done.probe_on", { networks: formatList(networkNames()) })
                  : t("setup.done.probe_none")}
              </div>
            </Show>
          </Row>
          <Row label={t("setup.done.cluster")}>{t("setup.cluster.new")}</Row>
        </dl>
        <Show when={w.state.profile === "lab"}>
          <div class="wz-help gap">{t("setup.done.lab_note")}</div>
        </Show>
      </div>
    </div>
  );
}
