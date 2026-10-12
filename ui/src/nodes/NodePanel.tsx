// One node, docked beside the node list (/nodes/<id>): its roles and address, the live
// connection (since when, the address the controller sees, the agreed protocol major, the
// version, the last heartbeat, the observation buffer), the certificate with its days left,
// the protocol negotiation with a refused handshake, and revocation for administrators.
import { A } from "@solidjs/router";
import { createSignal, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { getNode, revokeNode, type NodeView } from "../api/nodes";
import { errorMessage } from "../api/problem";
import { isAdmin } from "../auth/session";
import { ConfirmDialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { TimeAgo } from "../grid/cells";
import { formatBytes } from "./format";
import { formatDateTime, formatNumber, t } from "../i18n";
import { nodeScanPath } from "../scans/model";
import { certificateState, linkIcon, linkState, linkWord, roleWord } from "./model";

export function LinkBadge(props: { node: Pick<NodeView, "connected" | "protocol"> }) {
  const s = () => linkState(props.node);
  return (
    <span class={`node-link ${s()}`} data-state={s()} data-testid="node-link">
      <Icon name={linkIcon(s())} size="xs" />
      {linkWord(s())}
    </span>
  );
}

export function CertificateText(props: { node: Pick<NodeView, "certificate"> }) {
  const state = () => certificateState(props.node.certificate);
  return (
    <span class="node-cert" classList={{ due: state().renewalDue }} data-due={state().renewalDue ? "true" : "false"} title={formatDateTime(props.node.certificate.not_after)}>
      <Show when={state().renewalDue}>
        <Icon name="alert" size="xs" />{" "}
      </Show>
      {state().expired ? t("nodes.cert.expired") : t("nodes.cert.days_left", { days: state().daysLeft })}
    </span>
  );
}

export function NodePanel(props: { id: string; onClose: () => void; onRevoked: () => void }) {
  const live = createLiveQuery<NodeView>({
    topics: ["cluster"],
    fetch: async (signal) => {
      const node = await getNode(props.id, signal);
      return { value: node, revision: node.revision };
    },
  });
  // Reading `latest` of a failed load throws the error at the reader; the panel shows it instead.
  const node = () => (live.value.error ? undefined : live.value.latest);
  const [confirm, setConfirm] = createSignal(false);
  const [busy, setBusy] = createSignal(false);

  const revoke = async (n: NodeView) => {
    setBusy(true);
    try {
      await revokeNode(n.id);
      toast({ kind: "ok", title: t("nodes.revoke.done", { name: n.name }) });
      setConfirm(false);
      props.onRevoked();
    } catch (err) {
      toast({ kind: "bad", title: t("nodes.revoke.failed", { name: n.name }), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <aside
      class="panel node-panel"
      aria-label={t("nodes.panel.label")}
      data-testid="node-panel"
      data-id={props.id}
      onKeyDown={(e) => {
        if (e.key === "Escape" && !document.querySelector("[aria-modal='true']")) {
          e.stopPropagation();
          props.onClose();
        }
      }}
    >
      <Show
        when={node()}
        fallback={
          <div class="panel-body section">
            <Show when={live.value.error} fallback={<p class="muted" role="status">{t("common.loading")}</p>}>
              <ErrorNotice error={live.value.error} />
            </Show>
            <button type="button" class="btn" onClick={() => props.onClose()}>
              {t("common.action.close")}
            </button>
          </div>
        }
      >
        {(n) => (
          <>
            <div class="panel-head">
              <div class="grow">
                <h2 class="mono">{n().name}</h2>
                <div class="meta">
                  {t("nodes.panel.id", { id: n().id })} · <LinkBadge node={n()} />
                </div>
              </div>
              <div class="acts">
                <button type="button" class="icon-btn" aria-label={t("common.action.close")} title={t("common.action.close")} onClick={() => props.onClose()}>
                  <Icon name="x" />
                </button>
              </div>
            </div>
            <div class="panel-body">
              <Show when={n().protocol.mismatch}>
                {(m) => (
                  <div class="section">
                    <Notice kind="bad" testid="node-mismatch">
                      {t("nodes.panel.mismatch", {
                        theirs: m().theirs.join(", "),
                        ours: m().ours.join(", "),
                        version: m().version,
                        at: formatDateTime(m().at),
                      })}
                    </Notice>
                  </div>
                )}
              </Show>
              <section class="section" aria-labelledby="node-about">
                <h3 id="node-about">{t("nodes.panel.about")}</h3>
                <dl class="kv">
                  <dt>{t("nodes.col.roles")}</dt>
                  <dd>{n().roles.map(roleWord).join(", ")}</dd>
                  <dt>{t("nodes.col.address")}</dt>
                  <dd class="mono">{n().address ?? "–"}</dd>
                  <dt>{t("nodes.col.version")}</dt>
                  <dd class="mono">{n().version ?? "–"}</dd>
                  <dt>{t("nodes.col.last_seen")}</dt>
                  <dd>
                    <TimeAgo at={n().last_seen} />
                  </dd>
                  <dt>{t("nodes.panel.enrolled")}</dt>
                  <dd>
                    <TimeAgo at={n().enrolled_at} />
                  </dd>
                </dl>
              </section>
              <section class="section" aria-labelledby="node-connection" data-testid="node-connection">
                <h3 id="node-connection">{t("nodes.panel.connection")}</h3>
                <Show when={n().connection} fallback={<p class="muted">{t("nodes.panel.not_connected")}</p>}>
                  {(c) => (
                    <dl class="kv">
                      <dt>{t("nodes.panel.since")}</dt>
                      <dd>
                        <TimeAgo at={c().since} />
                      </dd>
                      <dt>{t("nodes.panel.peer")}</dt>
                      <dd class="mono">{c().peer ?? "–"}</dd>
                      <dt>{t("nodes.panel.major")}</dt>
                      <dd class="num">{c().major}</dd>
                      <dt>{t("nodes.panel.last_beat")}</dt>
                      <dd>
                        <TimeAgo at={c().last_beat} />
                      </dd>
                      <dt>{t("nodes.panel.buffer")}</dt>
                      <dd data-testid="node-buffer">
                        {t("nodes.panel.buffer_value", { batches: c().buffered_batches, size: formatBytes(c().buffered_bytes) })}
                      </dd>
                      <Show when={c().dropped_batches > 0}>
                        <dt>{t("nodes.panel.dropped")}</dt>
                        <dd class="num">{formatNumber(c().dropped_batches)}</dd>
                      </Show>
                    </dl>
                  )}
                </Show>
              </section>
              <section class="section" aria-labelledby="node-cert" data-testid="node-certificate">
                <h3 id="node-cert">{t("nodes.panel.certificate")}</h3>
                <dl class="kv">
                  <dt>{t("nodes.col.certificate")}</dt>
                  <dd>
                    <CertificateText node={n()} />
                  </dd>
                  <dt>{t("nodes.panel.valid")}</dt>
                  <dd>{t("nodes.panel.valid_range", { from: formatDateTime(n().certificate.not_before), to: formatDateTime(n().certificate.not_after) })}</dd>
                  <dt>{t("nodes.panel.serial")}</dt>
                  <dd class="mono">{n().certificate.serial}</dd>
                  <dt>{t("nodes.panel.renewed")}</dt>
                  <dd>
                    <TimeAgo at={n().renewed_at} />
                  </dd>
                </dl>
                <Show when={certificateState(n().certificate).renewalDue}>
                  <p class="muted">{t("nodes.panel.renewal_due")}</p>
                </Show>
              </section>
              <Show when={n().roles.includes("probe")}>
                <section class="section" aria-labelledby="node-scan">
                  <h3 id="node-scan">{t("nodes.scan.panel.title")}</h3>
                  <p class="muted">{t("nodes.scan.panel.hint")}</p>
                  <div class="row-actions">
                    <A href={nodeScanPath(n().id)} class="btn" data-testid="node-scan-config">
                      <Icon name="scan" />
                      {t("nodes.scan.panel.link")}
                    </A>
                  </div>
                </section>
              </Show>
              <Show when={isAdmin()}>
                <section class="section" aria-labelledby="node-revoke">
                  <h3 id="node-revoke">{t("nodes.revoke.title")}</h3>
                  <p class="muted">{t("nodes.revoke.hint")}</p>
                  <div class="row-actions">
                    <button type="button" class="btn danger" data-testid="node-revoke" onClick={() => setConfirm(true)}>
                      <Icon name="trash" />
                      {t("nodes.revoke.action")}
                    </button>
                  </div>
                </section>
              </Show>
            </div>
            <Show when={confirm()}>
              <ConfirmDialog
                title={t("nodes.revoke.confirm_title", { name: n().name })}
                body={<p>{t("nodes.revoke.confirm_body")}</p>}
                confirmLabel={t("nodes.revoke.confirm")}
                cancelLabel={t("common.action.cancel")}
                danger
                busy={busy()}
                onClose={() => setConfirm(false)}
                onConfirm={() => void revoke(n())}
              />
            </Show>
          </>
        )}
      </Show>
    </aside>
  );
}
