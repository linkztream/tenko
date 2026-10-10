// One secret (IAM-15): the facts the vault keeps about it, what uses it and the same actions as
// the list. Never the value; that is the reveal. The references follow the `secrets` topic
// (bindings change there) and the `ipam` topic (a host is renamed or deleted).
import { A } from "@solidjs/router";
import { Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { formatDateTime, formatRelative, t } from "../i18n";
import { secretReferences, type OperatorSecret, type SecretReferences } from "./api";
import { kindText, originText } from "./model";
import { Dash, LastReveal, SecretActions, TagList } from "./Parts";
import { referenceCount, ReferenceLists } from "./References";
import { secretsPath } from "./paths";
import "./secrets.css";

/** A time with its relative form; the exact time is the tooltip. */
function When(props: { at: string }) {
  return <span title={formatDateTime(props.at)}>{`${formatDateTime(props.at)} (${formatRelative(props.at)})`}</span>;
}

export function SecretDetail(props: {
  secret: OperatorSecret;
  canWrite: boolean;
  checking: boolean;
  onReveal: (secret: OperatorSecret) => void;
  onEdit: (secret: OperatorSecret) => void;
  onReplace: (secret: OperatorSecret) => void;
  onDelete: (secret: OperatorSecret) => void;
}) {
  const references = createLiveQuery<SecretReferences>({
    topics: ["secrets", "ipam"],
    fetch: async (signal) => ({ value: await secretReferences(props.secret.id, signal) }),
  });
  const loaded = () =>
    references.value.state === "ready" || references.value.state === "refreshing" ? references.value() : undefined;

  return (
    <section
      class="secret-detail card"
      data-testid="secret-detail"
      data-id={props.secret.id}
      data-key={props.secret.name}
      aria-label={t("secrets.detail.label", { name: props.secret.name })}
    >
      <div class="secret-detail-head">
        <h2>{props.secret.name}</h2>
        <A
          class="icon-btn"
          href={secretsPath()}
          aria-label={t("secrets.detail.close")}
          title={t("secrets.detail.close")}
          data-testid="secret-detail-close"
        >
          <Icon name="x" />
        </A>
      </div>

      <dl class="kv">
        <dt>{t("secrets.col.kind")}</dt>
        <dd data-testid="secret-kind">{kindText(props.secret.kind)}</dd>
        <dt>{t("secrets.col.user")}</dt>
        <dd class="mono" data-testid="secret-username">
          <Show when={props.secret.username} fallback={<Dash label={t("secrets.no_user")} />}>
            {(name) => name()}
          </Show>
        </dd>
        <dt>{t("secrets.col.tags")}</dt>
        <dd>
          <TagList tags={props.secret.tags} />
        </dd>
        <dt>{t("secrets.field.notes")}</dt>
        <dd class="secret-notes" data-testid="secret-notes">
          <Show when={props.secret.notes} fallback={<span class="muted">{t("common.none")}</span>}>
            {(notes) => notes()}
          </Show>
        </dd>
        <dt>{t("secrets.field.origin")}</dt>
        <dd>{originText(props.secret.origin)}</dd>
        <dt>{t("secrets.field.created")}</dt>
        <dd>
          <When at={props.secret.created_at} />
        </dd>
        <dt>{t("secrets.col.updated")}</dt>
        <dd>
          <When at={props.secret.updated_at} />
        </dd>
        <dt>{t("secrets.field.value_updated")}</dt>
        <dd>
          <When at={props.secret.value_updated_at} />
        </dd>
        <dt>{t("secrets.col.revealed")}</dt>
        <dd>
          <LastReveal secret={props.secret} />
        </dd>
      </dl>

      <SecretActions
        secret={props.secret}
        canWrite={props.canWrite}
        checking={props.checking}
        danger
        onReveal={props.onReveal}
        onEdit={props.onEdit}
        onReplace={props.onReplace}
        onDelete={props.onDelete}
      />

      <div class="secret-refs" data-testid="secret-references-section">
        <h3>{t("secrets.refs.title")}</h3>
        <ErrorNotice error={references.value.error} />
        <Show
          when={loaded()}
          fallback={
            <Show when={!references.value.error}>
              <p class="muted" role="status">
                {t("common.loading")}
              </p>
            </Show>
          }
        >
          {(refs) => (
            <Show
              when={referenceCount(refs()) > 0}
              fallback={
                <p class="muted" data-testid="secret-unused">
                  {t("secrets.refs.none")}
                </p>
              }
            >
              <ReferenceLists references={refs()} />
            </Show>
          )}
        </Show>
      </div>
    </section>
  );
}
