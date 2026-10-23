// The trust anchors of the recursion page (WP10.4): one card per zone (the root first, with the
// keys shipped in the release and what RFC 5011 made of them; operator anchors for private zones
// after it), each key with its tag, algorithm, form (a DS digest or a DNSKEY), RFC 5011 state and
// since when, its source and when it was last seen in the zone; the times of the zone's last and
// next query. Those who hold `dns.keys` refresh a zone now (RFC 5011 at once), add a key (a DS or
// a DNSKEY record) and remove a zone's anchor after a confirmation. The root may be replaced or
// removed under the Lab profile only; elsewhere its actions say why not
// (`dns.trust_anchor.root_protected`). The `dns` topic keeps the list live, so the states the
// leader service writes appear without a reload.
import { createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { ApiError, errorMessage } from "../../api/problem";
import { session } from "../../auth/session";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { ErrorNotice, Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDateTime, formatRelative, t } from "../../i18n";
import { mayKeys } from "../access";
import { DnsProblem, moduleOff, describedBy, Field } from "../Parts";
import {
  addAnchor,
  isRootZone,
  keyCounts,
  keyShape,
  listAnchors,
  refreshAnchor,
  removeAnchor,
  zoneInput,
  type AnchorKey,
  type TrustAnchorItem,
} from "./anchors";

/** Whether the profile in force lets the root's anchor be replaced or removed. */
function labProfile(): boolean {
  return session()?.profile === "lab";
}

function Source(props: { anchorKey: AnchorKey }) {
  const source = () => props.anchorKey.source;
  return (
    <Show when={source().kind === "shipped"} fallback={t(`dns.anchor.source.${source().kind === "operator" ? "operator" : "rfc5011"}`)}>
      {t("dns.anchor.source.shipped", { release: (source() as { release: string }).release })}
    </Show>
  );
}

function Keys(props: { anchor: TrustAnchorItem }) {
  return (
    <div class="table-wrap">
      <table class="plain rec-table" data-testid="dns-anchor-keys">
        <caption class="sr-only">{t("dns.anchor.keys_of", { zone: props.anchor.zone })}</caption>
        <thead>
          <tr>
            <th scope="col">{t("dns.anchor.col.tag")}</th>
            <th scope="col">{t("dns.anchor.col.algorithm")}</th>
            <th scope="col">{t("dns.anchor.col.form")}</th>
            <th scope="col">{t("dns.anchor.col.state")}</th>
            <th scope="col">{t("dns.anchor.col.source")}</th>
            <th scope="col">{t("dns.anchor.col.seen")}</th>
          </tr>
        </thead>
        <tbody>
          <For each={props.anchor.keys}>
            {(key) => (
              <tr data-testid="dns-anchor-key" data-key={key.key_tag} data-state={key.state}>
                <td class="mono">{key.key_tag}</td>
                <td class="mono">{key.algorithm}</td>
                <td>
                  {key.data.kind === "ds" ? t("dns.anchor.form.ds", { digest: key.digest_type ?? 0 }) : t("dns.anchor.form.dnskey")}
                </td>
                <td class="nowrap">
                  <span
                    class="tag"
                    classList={{ accent: key.state === "valid", discrepancy: key.state === "revoked" || key.state === "missing" }}
                    data-testid="dns-anchor-state"
                    title={t("dns.anchor.state_since", { time: formatDateTime(key.state_since) })}
                  >
                    {t(`dns.anchor.state.${key.state}`)}
                  </span>{" "}
                  <span class="muted">{formatRelative(key.state_since)}</span>
                </td>
                <td>
                  <Source anchorKey={key} />
                </td>
                <td class="nowrap">
                  <Show when={key.last_seen} fallback={<span class="muted">{t("dns.anchor.never_seen")}</span>}>
                    {(seen) => formatRelative(seen())}
                  </Show>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}

function AnchorCard(props: { anchor: TrustAnchorItem; onRemove: () => void; onChanged: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const root = () => isRootZone(props.anchor.zone);
  const protectedRoot = () => root() && !labProfile();
  const counts = () => keyCounts(props.anchor);
  const refresh = async () => {
    if (busy()) return;
    setBusy(true);
    try {
      await refreshAnchor(props.anchor.zone);
      toast({ kind: "ok", title: t("dns.anchor.refresh_sent", { zone: props.anchor.zone }) });
      props.onChanged();
    } catch (err) {
      toast({ kind: "bad", title: t("dns.anchor.refresh_failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card rec-anchor" data-testid="dns-anchor" data-key={props.anchor.zone} data-valid={counts().valid} data-pending={counts().pending}>
      <div class="rec-anchor-head">
        <h3>
          <span class="mono">{props.anchor.zone}</span>
          <Show when={root()}>
            <span class="muted"> {t("dns.anchor.root")}</span>
          </Show>
        </h3>
        <Show when={mayKeys()}>
          <div class="rec-anchor-actions">
            <button type="button" class="btn sm" data-testid="dns-anchor-refresh" disabled={busy()} onClick={() => void refresh()}>
              {t("dns.anchor.refresh")}
            </button>
            <button
              type="button"
              class="btn sm danger"
              data-testid="dns-anchor-remove"
              disabled={protectedRoot()}
              aria-describedby={protectedRoot() ? "dns-anchor-root-protected" : undefined}
              onClick={() => props.onRemove()}
            >
              {t("dns.anchor.remove")}
            </button>
          </div>
        </Show>
      </div>
      <dl class="kv rec-anchor-times">
        <dt>{t("dns.anchor.last_query")}</dt>
        <dd data-testid="dns-anchor-last">{props.anchor.last_query ? formatDateTime(props.anchor.last_query) : t("dns.anchor.never")}</dd>
        <dt>{t("dns.anchor.next_query")}</dt>
        <dd data-testid="dns-anchor-next">{props.anchor.next_query ? formatDateTime(props.anchor.next_query) : t("dns.anchor.never")}</dd>
      </dl>
      <Show when={counts().pending > 0}>
        <p class="muted" data-testid="dns-anchor-pending">
          {t("dns.anchor.pending", { count: counts().pending })}
        </p>
      </Show>
      <Show when={protectedRoot() && mayKeys()}>
        <p class="muted" id="dns-anchor-root-protected" data-testid="dns-anchor-root-protected">
          {t("errors.dns.trust_anchor.root_protected")}
        </p>
      </Show>
      <Keys anchor={props.anchor} />
    </section>
  );
}

/** The form field a refusal of the server names, for `dns.trust_anchor.invalid`. */
function refusedField(err: unknown): "zone" | "key" | undefined {
  if (!(err instanceof ApiError) || err.code !== "dns.trust_anchor.invalid") return undefined;
  return err.params.field === "zone" ? "zone" : "key";
}

export function AddAnchorDialog(props: { onClose: () => void; onDone: () => void }) {
  let zoneInputEl!: HTMLInputElement;
  const [zone, setZone] = createSignal("");
  const [kind, setKind] = createSignal<"ds" | "dnskey">("ds");
  const [record, setRecord] = createSignal("");
  const [replaceRoot, setReplaceRoot] = createSignal(false);
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const root = () => zoneInput(zone()) === ".";

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const name = zoneInput(zone());
    const e: Record<string, string> = {};
    if (name === null) e.zone = t("dns.anchor.check.zone");
    if (!keyShape(kind(), record())) e.key = t(`dns.anchor.check.${kind()}`);
    setErrors(e);
    if (Object.keys(e).length > 0 || name === null) return;
    setBusy(true);
    setError(undefined);
    try {
      const body = { zone: name, [kind()]: record().trim(), ...(name === "." && replaceRoot() ? { replace_root: true } : {}) };
      await addAnchor(body);
      toast({ kind: "ok", title: t("dns.anchor.added", { zone: name }) });
      props.onDone();
    } catch (err) {
      const field = refusedField(err);
      if (field) setErrors({ [field]: t("errors.dns.trust_anchor.invalid") });
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("dns.anchor.add_title")} onClose={props.onClose} class="dialog wide dns-dialog" testid="dialog-anchor-add" initialFocus={() => zoneInputEl}>
      <h2 class="dialog-title">{t("dns.anchor.add_title")}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        <Field id="anchor-zone" label={t("dns.anchor.field.zone")} error={errors().zone} help={t("dns.anchor.field.zone_help")}>
          <input
            ref={zoneInputEl}
            id="dns-f-anchor-zone"
            class="input mono"
            value={zone()}
            placeholder={t("dns.cache.suffix_placeholder")}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().zone ? "true" : undefined}
            aria-describedby={describedBy("anchor-zone", errors().zone, "help")}
            data-testid="field-anchor-zone"
            onInput={(ev) => setZone(ev.currentTarget.value)}
          />
        </Field>
        <fieldset class="dns-modes">
          <legend>{t("dns.anchor.field.form")}</legend>
          <For each={["ds", "dnskey"] as const}>
            {(k) => (
              <label class="choice">
                <input type="radio" name="dns-anchor-kind" checked={kind() === k} data-testid={`field-anchor-kind-${k}`} onChange={() => setKind(k)} />
                <span>{t(`dns.anchor.field.form_${k}`)}</span>
              </label>
            )}
          </For>
        </fieldset>
        <Field id="anchor-key" label={t(`dns.anchor.field.${kind()}`)} error={errors().key} help={t(`dns.anchor.field.${kind()}_help`)}>
          <textarea
            id="dns-f-anchor-key"
            class="input mono"
            rows={3}
            value={record()}
            spellcheck={false}
            aria-invalid={errors().key ? "true" : undefined}
            aria-describedby={describedBy("anchor-key", errors().key, "help")}
            data-testid="field-anchor-key"
            onInput={(ev) => setRecord(ev.currentTarget.value)}
          />
        </Field>
        <Show when={root()}>
          <Show
            when={labProfile()}
            fallback={
              <Notice kind="warn" role="status" testid="dns-anchor-root-note">
                {t("errors.dns.trust_anchor.root_protected")}
              </Notice>
            }
          >
            <div class="field">
              <label class="choice">
                <input type="checkbox" checked={replaceRoot()} data-testid="field-anchor-replace-root" onChange={(e) => setReplaceRoot(e.currentTarget.checked)} />
                <span>{t("dns.anchor.field.replace_root")}</span>
              </label>
              <span class="help">{t("dns.anchor.field.replace_root_help")}</span>
            </div>
          </Show>
        </Show>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dns.anchor.add")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function RemoveAnchorDialog(props: { anchor: TrustAnchorItem; onClose: () => void; onDone: () => void }) {
  const anchor = untrack(() => props.anchor);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dns.anchor.remove_title", { zone: anchor.zone })}
      testid="dialog-anchor-remove"
      danger
      busy={busy()}
      confirmLabel={t("dns.anchor.remove_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        removeAnchor(anchor.zone)
          .then(() => {
            toast({ kind: "ok", title: t("dns.anchor.removed", { zone: anchor.zone }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{isRootZone(anchor.zone) ? t("dns.anchor.remove_root_body") : t("dns.anchor.remove_body", { zone: anchor.zone })}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}

export function AnchorsSection() {
  const query = createLiveQuery({ topics: ["dns"], fetch: (signal) => listAnchors(signal).then((page) => ({ value: page.items, revision: page.revision })) });
  const [dialog, setDialog] = createSignal<{ kind: "add" } | { kind: "remove"; anchor: TrustAnchorItem } | null>(null);
  const anchors = () => latest(query);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };
  return (
    <section class="page-section rec-anchors" aria-labelledby="dns-recursion-anchors-title" data-testid="dns-recursion-anchors">
      <div class="rec-status-head">
        <h2 id="dns-recursion-anchors-title">{t("dns.recursion.trust_anchors.title")}</h2>
        <Show when={mayKeys() && !query.value.error}>
          <button type="button" class="btn" data-testid="dns-anchor-add" onClick={() => setDialog({ kind: "add" })}>
            {t("dns.anchor.add")}
          </button>
        </Show>
      </div>
      <p class="muted">{t("dns.anchor.lede")}</p>
      <Show when={query.value.error}>
        <Show when={moduleOff(query.value.error)} fallback={<ErrorNotice error={query.value.error} />}>
          <DnsProblem error={query.value.error} />
        </Show>
      </Show>
      <Show when={anchors()}>
        {(list) => (
          <Show
            when={list().length > 0}
            fallback={
              <p class="muted" data-testid="dns-recursion-anchors-count" data-state="none">
                {t("dns.recursion.trust_anchors.none")}
              </p>
            }
          >
            <div class="rec-anchor-list" data-testid="dns-recursion-anchors-count" data-state="listed" data-count={list().length}>
              <For each={list()}>
                {(anchor) => <AnchorCard anchor={anchor} onRemove={() => setDialog({ kind: "remove", anchor })} onChanged={() => query.refetch()} />}
              </For>
            </div>
          </Show>
        )}
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "add" ? (
            <AddAnchorDialog onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <RemoveAnchorDialog anchor={d.anchor} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </section>
  );
}
