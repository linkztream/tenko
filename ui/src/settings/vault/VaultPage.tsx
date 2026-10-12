// The settings page for the vault keys (WP3.11b, IAM-15; docs/secrets.md): the key-encryption
// key of the controller that answers (`GET /system/kek`), how every controller of the
// installation protects its key, the generations, and the online rotation (`POST
// /system/kek/rotate`), which needs a sign-in within the last five minutes. A refused rotation
// (`auth.step_up_required`) shows a notice with a way to sign in again. Administrators only.
import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery, latest } from "../../api/live";
import { isApiError } from "../../api/problem";
import type { components } from "../../api/generated/schema";
import { signOut } from "../../auth/session";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { formatDateTime, formatNumber, formatRelative, t, tDynamic } from "../../i18n";
import { RunDialog } from "../UserDialogs";
import { SettingsNav } from "../SettingsNav";
import "../settings.css";
import "./vault.css";

type S = components["schemas"];
type KekStatus = S["KekStatusView"];
type Protection = S["KekProtectionView"];
type Phase = S["KekRotationPhase"];

/** How often the page reads the status while a rotation runs. */
export const ROTATION_POLL_MS = 2000;

/** The words of a protection, by its stable code; an unknown code shows the server's text. */
export function protectionText(protection: Protection): string {
  return tDynamic(`vault.protection.${protection.code}`) ?? protection.text;
}

/** The words of a provider: DPAPI, systemd-creds, the systemd credential, a key file. */
export function providerText(provider: string): string {
  return tDynamic(`vault.provider.${provider}`) ?? provider;
}

/** The words of a warning of the status: its translation with the parameters, else the detail. */
export function warningText(warning: S["StatusWarning"]): string {
  const key = `vault.warning.${warning.code.replace(/^vault\.kek\./, "").replace(/\./g, "_")}`;
  return tDynamic(key, warning.params ?? {}) ?? warning.detail;
}

/** Whether a rotation is still on its way. */
export function rotating(phase: Phase | undefined): boolean {
  return phase === "requested" || phase === "distributing" || phase === "rewrapping";
}

function ProtectionLabel(props: { protection: Protection }) {
  return (
    <span data-testid="vault-protection" data-code={props.protection.code}>
      {protectionText(props.protection)}
      <Show when={props.protection.weak}>
        {" "}
        <span class="tag conflict">{t("vault.weak")}</span>
      </Show>
    </span>
  );
}

export default function VaultPage() {
  const status = createLiveQuery<KekStatus>({
    topics: ["system"],
    fetch: async (signal) => ({ value: await api.get("/api/v1/system/kek", { signal }) }),
  });
  const [confirming, setConfirming] = createSignal(false);
  const [stepUp, setStepUp] = createSignal(false);
  const current = () => latest(status);
  const phase = () => current()?.rotation?.phase;

  // While a rotation runs, read the status on a timer as well: the phases change on the leader.
  createEffect(() => {
    if (!rotating(phase())) return;
    const timer = setInterval(() => status.refetch(), ROTATION_POLL_MS);
    onCleanup(() => clearInterval(timer));
  });

  const rotate = async () => {
    try {
      await api.post("/api/v1/system/kek/rotate");
      setStepUp(false);
      status.refetch();
      toast({ kind: "ok", title: t("vault.rotation.requested") });
    } catch (err) {
      if (isApiError(err, "auth.step_up_required")) {
        setStepUp(true);
        setConfirming(false);
        return;
      }
      throw err;
    }
  };

  return (
    <div class="page" data-testid="page-vault">
      <PageHead title={t("vault.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted">{t("vault.lede")}</p>
        <ErrorNotice error={status.value.error} />
        <Show
          when={current()}
          fallback={
            <Show when={!status.value.error}>
              <p class="muted" role="status">
                {t("common.loading")}
              </p>
            </Show>
          }
        >
          {(kek) => (
            <>
              <Show when={kek().warnings.length > 0}>
                <div class="vault-warnings" data-testid="vault-warnings">
                  <For each={kek().warnings}>
                    {(warning) => (
                      <Notice kind="warn" role="status">
                        <span data-testid="vault-warning" data-code={warning.code}>
                          {warningText(warning)}
                        </span>
                      </Notice>
                    )}
                  </For>
                </div>
              </Show>

              <section class="page-section" aria-labelledby="vault-key" data-testid="vault-key">
                <h2 id="vault-key">{t("vault.key.heading", { node: kek().node })}</h2>
                <div class="card facts">
                  <dl class="kv">
                    <dt>{t("vault.key.provider")}</dt>
                    <dd data-testid="vault-provider">{providerText(kek().provider)}</dd>
                    <dt>{t("vault.key.protection")}</dt>
                    <dd>
                      <ProtectionLabel protection={kek().protection} />
                    </dd>
                    <Show when={kek().strongest}>
                      {(strongest) => (
                        <>
                          <dt>{t("vault.key.strongest")}</dt>
                          <dd>{protectionText(strongest())}</dd>
                        </>
                      )}
                    </Show>
                    <dt>{t("vault.key.active")}</dt>
                    <dd class="mono" data-testid="vault-active">
                      {kek().active}
                    </dd>
                    <dt>{t("vault.key.epoch")}</dt>
                    <dd class="num" data-testid="vault-epoch">
                      {formatNumber(kek().epoch)}
                    </dd>
                  </dl>
                </div>
              </section>

              <section class="page-section" aria-labelledby="vault-rotation" data-testid="vault-rotation">
                <div class="vault-head">
                  <h2 id="vault-rotation">{t("vault.rotation.heading")}</h2>
                  <button
                    type="button"
                    class="btn"
                    data-testid="vault-rotate"
                    disabled={rotating(phase())}
                    onClick={() => setConfirming(true)}
                  >
                    <Icon name="refresh" size="sm" />
                    {t("vault.rotation.rotate")}
                  </button>
                </div>
                <p class="muted">{t("vault.rotation.lede")}</p>
                <Show when={stepUp()}>
                  <div data-testid="vault-step-up">
                    <Notice kind="warn" role="alert" title={t("vault.step_up.title")}>
                      <p>{t("vault.step_up.body")}</p>
                      <button type="button" class="btn sm" data-testid="vault-sign-in-again" onClick={() => void signOut()}>
                        {t("vault.step_up.sign_in")}
                      </button>
                    </Notice>
                  </div>
                </Show>
                <Show when={kek().rotation} fallback={<p class="muted" data-testid="vault-rotation-none">{t("vault.rotation.never")}</p>}>
                  {(rotation) => (
                    <div class="card facts" data-testid="vault-rotation-state" data-phase={rotation().phase}>
                      <dl class="kv">
                        <dt>{t("vault.rotation.phase")}</dt>
                        <dd>
                          <span class={`tag ${rotation().phase === "failed" ? "conflict" : rotation().phase === "done" ? "ok" : "accent"}`}>
                            {t(`vault.phase.${rotation().phase}`)}
                          </span>
                        </dd>
                        <Show when={rotation().generation}>
                          {(generation) => (
                            <>
                              <dt>{t("vault.rotation.generation")}</dt>
                              <dd class="mono">{generation()}</dd>
                            </>
                          )}
                        </Show>
                        <dt>{t("vault.rotation.requested_at")}</dt>
                        <dd>
                          {formatRelative(rotation().requested_at)}{" "}
                          <span class="muted">({formatDateTime(rotation().requested_at)})</span>
                        </dd>
                        <dt>{t("vault.rotation.rewrapped")}</dt>
                        <dd class="num">{formatNumber(rotation().rewrapped)}</dd>
                        <Show when={rotation().waiting_for.length > 0}>
                          <dt>{t("vault.rotation.waiting_for")}</dt>
                          <dd>{rotation().waiting_for.join(", ")}</dd>
                        </Show>
                        <Show when={rotation().unreachable.length > 0}>
                          <dt>{t("vault.rotation.unreachable")}</dt>
                          <dd>{t("vault.rotation.unreachable_text", { nodes: rotation().unreachable.join(", ") })}</dd>
                        </Show>
                        <Show when={rotation().finished_at}>
                          {(at) => (
                            <>
                              <dt>{t("vault.rotation.finished_at")}</dt>
                              <dd>{formatDateTime(at())}</dd>
                            </>
                          )}
                        </Show>
                        <Show when={rotation().error}>
                          {(error) => (
                            <>
                              <dt>{t("vault.rotation.error")}</dt>
                              <dd>{error()}</dd>
                            </>
                          )}
                        </Show>
                      </dl>
                    </div>
                  )}
                </Show>
              </section>

              <section class="page-section" aria-labelledby="vault-controllers" data-testid="vault-controllers">
                <h2 id="vault-controllers">{t("vault.controllers.heading")}</h2>
                <div class="table-wrap">
                  <table class="plain">
                    <caption class="sr-only">{t("vault.controllers.heading")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("vault.controllers.col.node")}</th>
                        <th scope="col">{t("vault.key.provider")}</th>
                        <th scope="col">{t("vault.key.protection")}</th>
                        <th scope="col">{t("vault.key.strongest")}</th>
                        <th scope="col">{t("vault.controllers.col.updated")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={kek().controllers}>
                        {(c) => (
                          <tr data-testid="vault-controller" data-key={c.node}>
                            <td class="num">{c.node}</td>
                            <td>{providerText(c.provider)}</td>
                            <td>
                              <ProtectionLabel protection={c.protection} />
                              <Show when={c.protection.code !== c.strongest.code}>
                                {" "}
                                <span class="tag conflict" data-testid="vault-downgrade">
                                  {t("vault.downgrade")}
                                </span>
                              </Show>
                            </td>
                            <td>{protectionText(c.strongest)}</td>
                            <td>{formatRelative(c.updated_at)}</td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
              </section>

              <section class="page-section" aria-labelledby="vault-generations" data-testid="vault-generations">
                <h2 id="vault-generations">{t("vault.generations.heading")}</h2>
                <div class="table-wrap">
                  <table class="plain">
                    <caption class="sr-only">{t("vault.generations.heading")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("vault.generations.col.id")}</th>
                        <th scope="col">{t("vault.generations.col.state")}</th>
                        <th scope="col">{t("vault.key.protection")}</th>
                        <th scope="col">{t("vault.generations.col.created")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={kek().generations}>
                        {(g) => (
                          <tr data-testid="vault-generation" data-key={g.id} data-active={g.active ? "true" : "false"}>
                            <td class="mono">{g.id}</td>
                            <td>
                              {g.active ? t("vault.generations.active") : g.loaded ? t("vault.generations.loaded") : t("vault.generations.missing")}
                            </td>
                            <td>
                              <Show when={g.protection} fallback={<span class="muted">{t("common.none")}</span>}>
                                {(p) => <ProtectionLabel protection={p()} />}
                              </Show>
                            </td>
                            <td>
                              <Show when={g.created_at} fallback={<span class="muted">{t("common.none")}</span>}>
                                {(at) => formatDateTime(at())}
                              </Show>
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
                <Show when={kek().refused.length > 0}>
                  <Notice kind="bad" role="status" title={t("vault.refused.title")}>
                    <ul class="plain-list" data-testid="vault-refused">
                      <For each={kek().refused}>{(r) => <li class="mono">{r.file}</li>}</For>
                    </ul>
                  </Notice>
                </Show>
              </section>

              <Show when={confirming()}>
                <RunDialog
                  title={t("vault.rotation.confirm_title")}
                  body={
                    <>
                      <p>{t("vault.rotation.confirm_body")}</p>
                      <p class="muted">{t("vault.rotation.confirm_note")}</p>
                    </>
                  }
                  confirmLabel={t("vault.rotation.rotate")}
                  run={rotate}
                  onClose={() => setConfirming(false)}
                />
              </Show>
            </>
          )}
        </Show>
      </div>
    </div>
  );
}
