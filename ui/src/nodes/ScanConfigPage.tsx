// The scan configuration of one probe node (/nodes/<id>/scan; SCAN-05, SCAN-09, docs/scanning.md
// sections 7.5 and 7.6): whether the controllers hold a configuration and whether the probe
// applies it, the scope the probe reports, the remote kill switch, and the form that edits the
// configuration. Live on the `discovery` topic; administrators change, everyone else reads.
import { A, useParams } from "@solidjs/router";
import { createResource, createSignal, Show, untrack } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { getNode } from "../api/nodes";
import { ApiError, errorMessage } from "../api/problem";
import { paths } from "../app/paths";
import { isAdmin, session } from "../auth/session";
import { Icon } from "../components/Icon";
import { shortId } from "../components/Principal";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { toast } from "../components/toast";
import { formatDateTime, formatList, formatNumber, t } from "../i18n";
import { getScanConfig, listProbes, resumeNodeScans } from "../scans/api";
import type { KillSwitchView, ProbeConfigView, ProbeScope } from "../scans/model";
import { methodWord, ScanConfigForm } from "./ScanConfigForm";
import { StopProbeDialog } from "./StopProbeDialog";
import "./nodes.css";

const userNames = new Map<string, Promise<string | null>>();

/** A user by name: the signed-in one, else the account looked up once, else a short id. */
function UserName(props: { id: string }) {
  const me = () => session()?.user;
  const [name] = createResource(
    () => (me()?.id === props.id ? false : props.id),
    (id) => {
      let found = userNames.get(id);
      if (!found) {
        found = api
          .get("/api/v1/users/{id}", { path: { id } })
          .then((u) => u.display_name || u.name)
          .catch(() => null);
        userNames.set(id, found);
      }
      return found;
    },
  );
  return (
    <span class="principal" title={props.id}>
      {me()?.id === props.id ? (me()?.display_name || me()?.name) : (name() ?? shortId(props.id))}
    </span>
  );
}

function When(props: { at: string | null | undefined }) {
  return <Show when={props.at} fallback={<span class="muted">–</span>}>{(at) => <time datetime={at()}>{formatDateTime(at())}</time>}</Show>;
}

/** A list of prefixes or names in the data face, or "none". */
function Items(props: { items: readonly string[] }) {
  return (
    <Show when={props.items.length > 0} fallback={<span class="muted">{t("common.none")}</span>}>
      <span class="mono">{props.items.join(", ")}</span>
    </Show>
  );
}

function SyncCard(props: { view: ProbeConfigView }) {
  const v = () => props.view;
  return (
    <section class="card scan-card" aria-labelledby="scan-sync-h" data-testid="scan-config-sync" data-sync={v().in_sync ? "true" : "false"} data-stored={v().stored ? "true" : "false"}>
      <h2 id="scan-sync-h">{t("nodes.scan.sync.title")}</h2>
      <p class="scan-state">
        <Show
          when={v().in_sync}
          fallback={
            <span class="node-link disconnected" data-testid="scan-sync-state">
              <Icon name="clock" size="xs" />
              {t("nodes.scan.sync.not_in_sync")}
            </span>
          }
        >
          <span class="node-link connected" data-testid="scan-sync-state">
            <Icon name="check" size="xs" />
            {t("nodes.scan.sync.in_sync")}
          </span>
        </Show>
      </p>
      <Show when={v().stored} fallback={<p class="muted">{t("nodes.scan.sync.not_stored")}</p>}>
        <dl class="kv">
          <dt>{t("nodes.scan.sync.origin")}</dt>
          <dd data-testid="scan-sync-origin" data-origin={v().origin ?? ""}>
            {v().origin === "offer" ? t("nodes.scan.sync.origin_offer") : t("nodes.scan.sync.origin_api")}
          </dd>
          <dt>{t("nodes.scan.sync.revision")}</dt>
          <dd class="num" data-testid="scan-sync-revision">
            {v().revision ?? "–"}
          </dd>
          <dt>{t("nodes.scan.sync.updated_by")}</dt>
          <dd>
            <Show when={v().updated_by} fallback={<span class="muted">–</span>}>
              {(id) => <UserName id={id()} />}
            </Show>
          </dd>
          <dt>{t("nodes.scan.sync.updated_at")}</dt>
          <dd>
            <When at={v().updated_at} />
          </dd>
        </dl>
      </Show>
    </section>
  );
}

function AppliedCard(props: { applied: ProbeScope | null | undefined }) {
  return (
    <section class="card scan-card" aria-labelledby="scan-applied-h" data-testid="scan-config-applied">
      <h2 id="scan-applied-h">{t("nodes.scan.applied.title")}</h2>
      <Show when={props.applied} fallback={<p class="muted" data-testid="scan-applied-none">{t("nodes.scan.applied.none")}</p>}>
        {(a) => (
          <>
            <Show when={a().error}>
              {(message) => (
                <Notice kind="bad" role="alert" testid="scan-applied-error">
                  {t("nodes.scan.applied.error", { error: message() })}
                </Notice>
              )}
            </Show>
            <dl class="kv">
              <dt>{t("nodes.scan.applied.prefixes")}</dt>
              <dd data-testid="scan-applied-prefixes">
                <Items items={a().prefixes} />
              </dd>
              <dt>{t("nodes.scan.applied.exclude")}</dt>
              <dd data-testid="scan-applied-exclude">
                <Items items={a().exclude} />
              </dd>
              <dt>{t("nodes.scan.applied.methods")}</dt>
              <dd data-testid="scan-applied-methods">
                <Show when={a().methods.length > 0} fallback={<span class="muted">{t("common.none")}</span>}>
                  {formatList(a().methods.map((m) => methodWord(m as Parameters<typeof methodWord>[0], "name")))}
                </Show>
              </dd>
              <dt>{t("nodes.scan.applied.active")}</dt>
              <dd>{a().active ? t("common.yes") : t("common.no")}</dd>
              <dt>{t("nodes.scan.applied.origin")}</dt>
              <dd>{a().origin === "synced" ? t("nodes.scan.applied.origin_synced") : t("nodes.scan.applied.origin_local")}</dd>
              <dt>{t("nodes.scan.applied.revision")}</dt>
              <dd class="num" data-testid="scan-applied-revision">
                {formatNumber(a().revision)}
              </dd>
              <dt>{t("nodes.scan.applied.applied_at")}</dt>
              <dd>
                <When at={a().applied_at} />
              </dd>
              <dt>{t("nodes.scan.applied.reported_at")}</dt>
              <dd>
                <When at={a().reported_at} />
              </dd>
            </dl>
          </>
        )}
      </Show>
    </section>
  );
}

function KillSwitchCard(props: { node: number; name: string; switch: KillSwitchView; admin: boolean; onChanged: () => void }) {
  const [stopping, setStopping] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const k = () => props.switch;

  const resume = async () => {
    setBusy(true);
    try {
      await resumeNodeScans(props.node);
      toast({ kind: "ok", title: t("nodes.scan.resume.done", { name: props.name }) });
      props.onChanged();
    } catch (err) {
      toast({ kind: "bad", title: t("nodes.scan.resume.failed", { name: props.name }), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="card scan-card" aria-labelledby="scan-ks-h" data-testid="scan-kill-switch" data-state={k().stopped ? "stopped" : "running"}>
      <h2 id="scan-ks-h">{t("nodes.scan.ks.title")}</h2>
      <p class="scan-state">
        <Show
          when={k().stopped}
          fallback={
            <span class="node-link connected" data-testid="scan-ks-state">
              <Icon name="play" size="xs" />
              {t("nodes.scan.ks.running")}
            </span>
          }
        >
          <span class="node-link mismatch" data-testid="scan-ks-state">
            <Icon name="pause" size="xs" />
            {t("nodes.scan.ks.stopped")}
          </span>
        </Show>
      </p>
      <Show when={k().stopped || k().at}>
        <dl class="kv">
          <Show when={k().stopped}>
            <dt>{t("nodes.scan.ks.reason")}</dt>
            <dd data-testid="scan-ks-reason">{k().reason || <span class="muted">–</span>}</dd>
          </Show>
          <dt>{t("nodes.scan.ks.by")}</dt>
          <dd>
            <Show when={k().by} fallback={<span class="muted">–</span>}>
              {(id) => <UserName id={id()} />}
            </Show>
          </dd>
          <dt>{t("nodes.scan.ks.at")}</dt>
          <dd>
            <When at={k().at} />
          </dd>
          <dt>{t("nodes.scan.ks.confirmed")}</dt>
          <dd data-testid="scan-ks-confirmed" data-confirmed={k().confirmed ? "true" : "false"}>
            {k().confirmed ? t("nodes.scan.ks.confirmed_yes") : t("nodes.scan.ks.confirmed_no")}
          </dd>
        </dl>
      </Show>
      <Show when={props.admin}>
        <div class="row-actions">
          <Show
            when={k().stopped}
            fallback={
              <button type="button" class="btn danger" data-testid="scan-stop" onClick={() => setStopping(true)}>
                <Icon name="pause" />
                {t("nodes.scan.ks.stop")}
              </button>
            }
          >
            <button type="button" class="btn primary" disabled={busy()} data-testid="scan-resume" onClick={() => void resume()}>
              <Icon name="play" />
              {t("nodes.scan.ks.resume")}
            </button>
          </Show>
        </div>
      </Show>
      <Show when={stopping()}>
        <StopProbeDialog
          node={props.node}
          name={props.name}
          onClose={() => setStopping(false)}
          onStopped={() => {
            setStopping(false);
            props.onChanged();
          }}
        />
      </Show>
    </section>
  );
}

function ProbeScanConfig(props: { id: string }) {
  const node = Number(untrack(() => props.id));
  const valid = Number.isSafeInteger(node) && node > 0;
  const live = createLiveQuery<ProbeConfigView | null>({
    topics: ["discovery"],
    fetch: async (signal) => ({ value: valid ? await getScanConfig(node, signal) : null }),
  });
  // The name comes from the probe list, which names the controller's own probe too, else from the node.
  const [found] = createResource(async () => {
    if (!valid) return undefined;
    try {
      const probe = (await listProbes()).items.find((p) => p.node === node);
      if (probe) return probe.name;
    } catch {
      // Falls through to the node itself.
    }
    try {
      return (await getNode(node)).name;
    } catch {
      return undefined;
    }
  });
  const name = () => (found.error ? undefined : found()) ?? t("nodes.scan.node_fallback", { id: props.id });
  const admin = () => isAdmin();
  // Reading `latest` of a failed load throws the error at the reader, so the guarded accessor is used.
  const view = () => live.latest();
  const refused = () => {
    const e = live.value.error;
    return e instanceof ApiError && (e.status === 404 || e.status === 409) ? e : null;
  };
  const missing = () => (valid ? false : true);

  return (
    <div class="page" data-testid="page-scan-config" data-node={props.id}>
      <PageHead
        title={t("nodes.scan.title")}
        sub={<span class="mono">{name()}</span>}
        crumbs={
          <>
            <A href={paths.nodes()}>{t("shell.nav.nodes")}</A>
            <Icon name="chev-r" size="xs" />
            <A href={paths.node(props.id)} data-testid="scan-config-back">
              {t("nodes.scan.back", { name: name() })}
            </A>
          </>
        }
      />
      <div class="page-body">
        <Show when={missing() || refused()}>
          <Notice kind="info" role="status" testid="scan-config-not-probe" title={t("nodes.scan.not_probe.title")}>
            {refused()?.status === 409 ? t("nodes.scan.not_probe.body", { name: name() }) : t("nodes.scan.not_probe.missing")}
          </Notice>
        </Show>
        <Show when={!refused() && !missing() && live.value.error}>
          <div class="section">
            <ErrorNotice error={live.value.error} />
            <div class="row-actions">
              <button type="button" class="btn" onClick={() => live.refetch()}>
                {t("common.action.retry")}
              </button>
            </div>
          </div>
        </Show>
        <Show when={!missing() && !live.value.error && !view()}>
          <p class="muted" role="status">
            {t("common.loading")}
          </p>
        </Show>
        <Show when={view()}>
          {(v) => (
            <>
              <Show when={(v().lacking_secrets ?? []).length > 0}>
                <Notice kind="warn" role="status" testid="scan-config-lacking">
                  {t("nodes.scan.lacking", { count: (v().lacking_secrets ?? []).length, devices: formatList(v().lacking_secrets ?? []) })}
                </Notice>
              </Show>
              <div class="scan-cards">
                <SyncCard view={v()} />
                <AppliedCard applied={v().applied} />
                <KillSwitchCard node={node} name={name()} switch={v().kill_switch} admin={admin()} onChanged={() => live.refetch()} />
              </div>
              <section aria-labelledby="scan-form-h" class="scan-form-section">
                <h2 id="scan-form-h">{t("nodes.scan.form.title")}</h2>
                <ScanConfigForm node={node} view={v()} admin={admin()} onChanged={() => live.refetch()} />
              </section>
            </>
          )}
        </Show>
      </div>
    </div>
  );
}

export default function ScanConfigPage() {
  const params = useParams<{ id: string }>();
  // A different node in the URL starts the page over: its reads, its draft and its dialogs.
  return (
    <Show when={params.id} keyed>
      {(id) => <ProbeScanConfig id={id} />}
    </Show>
  );
}
