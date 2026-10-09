// One audit record (/audit/:seq): who did what, when, to which objects, with which result,
// the field changes as a before and after table, the context and the two hashes that chain
// the record to the one before it.
import { A, useParams } from "@solidjs/router";
import { createMemo, createResource, For, Match, Show, Switch } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { isApiError } from "../api/problem";
import type { AuditRecord, Principal } from "../api/types";
import { decodeSegment, paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { PrincipalLabel, shortId } from "../components/Principal";
import { formatDateTime, formatRelative, t } from "../i18n";
import { Dash, Maybe, OutcomeBadge } from "./cells";
import { isZeroHash, kindWord, principalSubject } from "./model";
import { objectFilter, objectLabel, objectViews } from "./objects";
import "./audit.css";

/** The seq of a path: decimal digits, at least 1. */
const SEQ = /^[1-9]\d*$/;

/** The principal as the variant `kind`, or undefined when it is another one. */
function asKind<K extends Principal["kind"]>(principal: Principal, kind: K): Extract<Principal, { kind: K }> | undefined {
  return principal.kind === kind ? (principal as Extract<Principal, { kind: K }>) : undefined;
}

function Id(props: { value: string | number }) {
  return <span class="mono">{props.value}</span>;
}

/** What is specific to the kind of principal: ids, the session and its strength, the owner. */
function PrincipalFacts(props: { principal: Principal }) {
  const p = () => props.principal;
  return (
    <>
      <dt>{t("audit.record.principal_kind")}</dt>
      <dd>{t(`audit.principal.kind.${p().kind}`)}</dd>
      <Show when={asKind(p(), "user")}>
        {(user) => (
          <>
            <dt>{t("audit.record.principal_id")}</dt>
            <dd>
              <Id value={user().id} />
            </dd>
            <dt>{t("audit.record.session")}</dt>
            <dd>
              <Id value={user().session} />
            </dd>
            <dt>{t("audit.record.strength")}</dt>
            <dd>{t(`audit.strength.${user().strength}`)}</dd>
          </>
        )}
      </Show>
      <Show when={asKind(p(), "token")}>
        {(token) => (
          <>
            <dt>{t("audit.record.principal_id")}</dt>
            <dd>
              <Id value={token().id} />
            </dd>
            <dt>{t("audit.record.owner")}</dt>
            <dd>
              <Id value={token().owner} />
            </dd>
          </>
        )}
      </Show>
      <Show when={asKind(p(), "system")}>
        {(system) => (
          <>
            <dt>{t("audit.record.component")}</dt>
            <dd>
              <Id value={system().component} />
            </dd>
            <Show when={system().on_behalf_of}>
              {(user) => (
                <>
                  <dt>{t("audit.record.on_behalf_of")}</dt>
                  <dd>
                    <Id value={user()} />
                  </dd>
                </>
              )}
            </Show>
          </>
        )}
      </Show>
      <Show when={asKind(p(), "node")}>
        {(node) => (
          <>
            <dt>{t("audit.record.principal_id")}</dt>
            <dd>
              <Id value={node().id} />
            </dd>
          </>
        )}
      </Show>
    </>
  );
}

function Content(props: { record: AuditRecord }) {
  const record = () => props.record;
  const draft = () => record().draft;
  const changes = () => draft().details?.changes ?? [];
  const context = () => Object.entries(draft().details?.context ?? {});
  const hasObjectColumn = () => changes().some((c) => c.object);
  const objects = createMemo(() => objectViews(record()));

  return (
    <div class="page-body">
      <section class="page-section" aria-labelledby="ar-overview">
        <h2 id="ar-overview">{t("audit.record.overview")}</h2>
        <dl class="kv audit-facts">
          <dt>{t("audit.col.time")}</dt>
          <dd>
            <time datetime={record().at}>{formatDateTime(record().at, { dateStyle: "long", timeStyle: "long" })}</time>
            <span class="muted">{formatRelative(record().at)}</span>
          </dd>
          <dt>{t("audit.col.action")}</dt>
          <dd>
            <span class="mono">{draft().action}</span>
          </dd>
          <dt>{t("audit.col.outcome")}</dt>
          <dd>
            <OutcomeBadge record={record()} />
          </dd>
          <dt>{t("audit.record.revision")}</dt>
          <dd>
            <span class="mono">{record().revision}</span>
          </dd>
          <dt>{t("audit.record.request")}</dt>
          <dd>
            <Maybe value={record().request} mono />
          </dd>
          <dt>{t("audit.col.source")}</dt>
          <dd>
            <Maybe value={draft().source_ip} mono />
          </dd>
        </dl>
      </section>

      <section class="page-section" aria-labelledby="ar-principal">
        <h2 id="ar-principal">{t("audit.col.principal")}</h2>
        <dl class="kv audit-facts">
          <dt>{t("audit.col.principal")}</dt>
          <dd>
            <PrincipalLabel principal={record().principal} />
            <A href={paths.audit({ principal: principalSubject(record().principal) })}>{t("audit.record.principal_log")}</A>
          </dd>
          <PrincipalFacts principal={record().principal} />
        </dl>
      </section>

      <section class="page-section" aria-labelledby="ar-objects">
        <h2 id="ar-objects">{t("audit.record.objects")}</h2>
        <Show when={objects().length > 0} fallback={<p class="muted">{t("audit.record.objects_none")}</p>}>
          <ul class="record-objects" data-testid="audit-objects">
            <For each={objects()}>
              {(view) => (
                <li class="record-object" data-kind={view.ref.kind}>
                  <span class="object-kind">{kindWord(view.ref.kind)}</span>
                  <Show
                    when={view.href}
                    fallback={
                      <span class="mono" title={view.ref.id}>
                        {view.text}
                      </span>
                    }
                  >
                    {(href) => (
                      <A class="mono" href={href()}>
                        {view.text}
                      </A>
                    )}
                  </Show>
                  <span class="mono muted">{view.ref.id}</span>
                  <A href={paths.audit({ object: objectFilter(view.ref) })}>{t("audit.record.object_log")}</A>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </section>

      <section class="page-section" aria-labelledby="ar-changes">
        <h2 id="ar-changes">{t("audit.changes.title")}</h2>
        <Show when={changes().length > 0} fallback={<p class="muted">{t("audit.changes.none")}</p>}>
          <div class="table-wrap">
            <table class="plain changes" data-testid="audit-changes" aria-label={t("audit.changes.table")}>
              <thead>
                <tr>
                  <Show when={hasObjectColumn()}>
                    <th scope="col">{t("audit.changes.object")}</th>
                  </Show>
                  <th scope="col">{t("audit.changes.field")}</th>
                  <th scope="col">{t("audit.changes.old")}</th>
                  <th scope="col">{t("audit.changes.new")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={changes()}>
                  {(change) => (
                    <tr>
                      <Show when={hasObjectColumn()}>
                        <td>
                          <Show when={change.object} fallback={<Dash />}>
                            {(ref) => (
                              <>
                                <span class="object-kind">{kindWord(ref().kind)}</span>{" "}
                                <span class="mono">{objectLabel(record(), ref()) ?? shortId(ref().id)}</span>
                              </>
                            )}
                          </Show>
                        </td>
                      </Show>
                      <td>
                        <span class="mono">{change.field}</span>
                      </td>
                      <td data-col="old">
                        <ChangeValue value={change.old} />
                      </td>
                      <td data-col="new">
                        <Show
                          when={change.old != null || change.new != null}
                          fallback={<span class="muted">{t("audit.changes.not_recorded")}</span>}
                        >
                          <ChangeValue value={change.new} />
                        </Show>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </section>

      <section class="page-section" aria-labelledby="ar-context">
        <h2 id="ar-context">{t("audit.context.title")}</h2>
        <Show when={context().length > 0} fallback={<p class="muted">{t("audit.context.none")}</p>}>
          <div class="table-wrap">
            <table class="plain changes" data-testid="audit-context" aria-label={t("audit.context.title")}>
              <thead>
                <tr>
                  <th scope="col">{t("audit.context.key")}</th>
                  <th scope="col">{t("audit.context.value")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={context()}>
                  {([key, value]) => (
                    <tr>
                      <td>
                        <span class="mono">{key}</span>
                      </td>
                      <td>{value}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </section>

      <section class="page-section" aria-labelledby="ar-hashes">
        <h2 id="ar-hashes">{t("audit.hashes.title")}</h2>
        <dl class="kv audit-facts">
          <dt>{t("audit.hashes.prev")}</dt>
          <dd>
            <span class="hash" data-testid="audit-prev-hash">
              {record().prev}
            </span>
            <Show when={isZeroHash(record().prev)}>
              <span class="muted">{t("audit.hashes.first")}</span>
            </Show>
          </dd>
          <dt>{t("audit.hashes.hash")}</dt>
          <dd>
            <span class="hash" data-testid="audit-hash">
              {record().hash}
            </span>
          </dd>
        </dl>
        <p class="muted">{t("audit.hashes.note")}</p>
      </section>
    </div>
  );
}

function ChangeValue(props: { value: string | null | undefined }) {
  return (
    <Show
      when={props.value != null}
      fallback={
        <span class="muted">
          <span aria-hidden="true">–</span>
          <span class="sr-only">{t("audit.changes.no_value")}</span>
        </span>
      }
    >
      <span class="mono">{props.value}</span>
    </Show>
  );
}

export default function RecordPage() {
  const params = useParams<{ seq: string }>();
  const seqText = () => decodeSegment(params.seq);
  const valid = () => SEQ.test(seqText());

  const [record, { refetch }] = createResource(
    () => (valid() ? seqText() : false),
    (seq) => api.get("/api/v1/audit/{seq}", { path: { seq } }),
  );
  // The newest record, to know where "next" ends; it moves while the page is open.
  const newest = createLiveQuery<number>({
    topics: ["audit"],
    fetch: async (signal) => {
      const page = await api.get("/api/v1/audit", { query: { limit: 1 }, signal });
      return { value: page.items[0]?.seq ?? 0, revision: typeof page.revision === "number" ? page.revision : undefined };
    },
  });
  const head = () => (newest.value.state === "ready" || newest.value.state === "refreshing" ? newest.value() : undefined);

  const current = () => {
    if (record.state !== "ready" && record.state !== "refreshing") return undefined;
    const r = record();
    return r && String(r.seq) === seqText() ? r : undefined;
  };
  const missing = () => !valid() || (isApiError(record.error) && record.error.status === 404);

  return (
    <div class="page audit-page audit-record" data-testid="page-audit-record">
      <PageHead
        crumbs={
          <nav class="crumbs-nav" aria-label={t("audit.record.crumbs")}>
            <A href={paths.audit()}>{t("audit.title")}</A>
            <Icon name="chev-r" size="xs" />
            <span aria-current="page">{valid() ? t("audit.record.title", { seq: seqText() }) : t("audit.title")}</span>
          </nav>
        }
        title={valid() ? t("audit.record.title", { seq: seqText() }) : t("audit.title")}
        actions={
          <Show when={current()}>
            {(r) => (
              <div class="step-links">
                <Show
                  when={r().seq > 1}
                  fallback={
                    <button type="button" class="btn sm" disabled>
                      <Icon name="chev-r" size="xs" class="flip" />
                      {t("audit.record.previous")}
                    </button>
                  }
                >
                  <A class="btn sm" href={paths.auditRecord(r().seq - 1)} data-testid="audit-prev">
                    <Icon name="chev-r" size="xs" class="flip" />
                    {t("audit.record.previous")}
                  </A>
                </Show>
                <Show
                  when={head() === undefined || r().seq < (head() ?? 0)}
                  fallback={
                    <button type="button" class="btn sm" disabled>
                      {t("audit.record.next")}
                      <Icon name="chev-r" size="xs" />
                    </button>
                  }
                >
                  <A class="btn sm" href={paths.auditRecord(r().seq + 1)} data-testid="audit-next">
                    {t("audit.record.next")}
                    <Icon name="chev-r" size="xs" />
                  </A>
                </Show>
              </div>
            )}
          </Show>
        }
      />
      <Switch>
        <Match when={missing()}>
          <div class="page-body" data-testid="audit-not-found">
            <Notice kind="warn" role="status">
              {t("audit.record.not_found", { seq: seqText().slice(0, 24) })}
            </Notice>
            <div class="form-row">
              <A class="btn" href={paths.audit()}>
                {t("audit.record.back")}
              </A>
              <Show when={(head() ?? 0) > 0}>
                <A class="btn" href={paths.auditRecord(head() ?? 0)}>
                  {t("audit.record.open_newest", { seq: String(head() ?? 0) })}
                </A>
              </Show>
            </div>
          </div>
        </Match>
        <Match when={record.error}>
          <div class="page-body">
            <ErrorNotice error={record.error} />
            <div class="form-row">
              <button type="button" class="btn" onClick={() => void refetch()}>
                {t("common.action.retry")}
              </button>
            </div>
          </div>
        </Match>
        <Match when={current()} keyed>
          {(r) => <Content record={r} />}
        </Match>
        <Match when={true}>
          <div class="page-body">
            <p class="muted" role="status">
              {t("audit.record.loading")}
            </p>
          </div>
        </Match>
      </Switch>
    </div>
  );
}
