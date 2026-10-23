// The negative trust anchors of the recursion page (WP10.4, RFC 7646): the zones whose failing
// validation is treated as insecure for a while, each with its expiry (when, and how long from
// now; one past its expiry shows as expired until the list is read again, since the server lists
// only the living ones), its reason,
// who created it and when. Those who hold `dns.keys` create one (the zone, a lifetime of at most
// seven days written as `12h` or `2d`, and the reason, which the form asks for) and delete one
// after a confirmation. The Hardened profile requires an expiry (TGL-12), which the lifetime
// always gives. The `dns` topic keeps the list live, so an expiry shows without a reload.
import { createSignal, For, onCleanup, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { ApiError } from "../../api/problem";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDateTime, formatRelative, t } from "../../i18n";
import { mayKeys } from "../access";
import { describedBy, DnsProblem, Field, moduleOff } from "../Parts";
import { createNta, deleteNta, isRootZone, listNtas, ntaExpired, NTA_REASON_MAX, parseLifetime, zoneInput, type NtaItem } from "./anchors";

/** The form field a refusal of the server names (`dns.nta.invalid` with `field`). */
function refusedField(err: unknown): "zone" | "expires" | "reason" | undefined {
  if (!(err instanceof ApiError) || err.code !== "dns.nta.invalid") return undefined;
  const field = err.params.field ?? "";
  if (field === "zone" || field === "reason") return field;
  if (field.startsWith("expir")) return "expires";
  return undefined;
}

export function NtaDialog(props: { onClose: () => void; onDone: () => void }) {
  let zoneEl!: HTMLInputElement;
  const [zone, setZone] = createSignal("");
  const [lifetime, setLifetime] = createSignal("1d");
  const [reason, setReason] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const name = zoneInput(zone());
    const seconds = parseLifetime(lifetime());
    const text = reason().trim();
    const e: Record<string, string> = {};
    if (name === null || zone().trim() === "") e.zone = t("dns.nta.check.zone");
    else if (isRootZone(name)) e.zone = t("dns.nta.check.root");
    if (seconds === null) e.expires = t("dns.nta.check.lifetime");
    if (text === "") e.reason = t("dns.nta.check.reason");
    else if (text.length > NTA_REASON_MAX) e.reason = t("dns.nta.check.reason_long", { max: NTA_REASON_MAX });
    setErrors(e);
    if (Object.keys(e).length > 0 || name === null || seconds === null) return;
    setBusy(true);
    setError(undefined);
    try {
      await createNta({ zone: name, expires_at: new Date(Date.now() + seconds * 1000).toISOString(), reason: text });
      toast({ kind: "ok", title: t("dns.nta.created", { zone: name }) });
      props.onDone();
    } catch (err) {
      const field = refusedField(err);
      if (field && err instanceof ApiError) setErrors({ [field]: err.params.reason ?? t("errors.dns.nta.invalid") });
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("dns.nta.add_title")} onClose={props.onClose} class="dialog wide dns-dialog" testid="dialog-nta-add" initialFocus={() => zoneEl}>
      <h2 class="dialog-title">{t("dns.nta.add_title")}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        <p class="muted">{t("dns.nta.add_lede")}</p>
        <Field id="nta-zone" label={t("dns.nta.field.zone")} error={errors().zone}>
          <input
            ref={zoneEl}
            id="dns-f-nta-zone"
            class="input mono"
            value={zone()}
            placeholder={t("dns.cache.suffix_placeholder")}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().zone ? "true" : undefined}
            aria-describedby={describedBy("nta-zone", errors().zone)}
            data-testid="field-nta-zone"
            onInput={(ev) => setZone(ev.currentTarget.value)}
          />
        </Field>
        <Field id="nta-expires" label={t("dns.nta.field.lifetime")} error={errors().expires} help={t("dns.nta.field.lifetime_help")}>
          <input
            id="dns-f-nta-expires"
            class="input mono"
            value={lifetime()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().expires ? "true" : undefined}
            aria-describedby={describedBy("nta-expires", errors().expires, "help")}
            data-testid="field-nta-lifetime"
            onInput={(ev) => setLifetime(ev.currentTarget.value)}
          />
        </Field>
        <Field id="nta-reason" label={t("dns.nta.field.reason")} error={errors().reason} help={t("dns.nta.field.reason_help")}>
          <textarea
            id="dns-f-nta-reason"
            class="input"
            rows={3}
            maxlength={NTA_REASON_MAX}
            value={reason()}
            aria-invalid={errors().reason ? "true" : undefined}
            aria-describedby={describedBy("nta-reason", errors().reason, "help")}
            data-testid="field-nta-reason"
            onInput={(ev) => setReason(ev.currentTarget.value)}
          />
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dns.nta.add")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteNtaDialog(props: { nta: NtaItem; onClose: () => void; onDone: () => void }) {
  const nta = untrack(() => props.nta);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dns.nta.delete_title", { zone: nta.zone })}
      testid="dialog-nta-delete"
      danger
      busy={busy()}
      confirmLabel={t("dns.nta.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteNta(nta.id)
          .then(() => {
            toast({ kind: "ok", title: t("dns.nta.deleted", { zone: nta.zone }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dns.nta.delete_body", { zone: nta.zone })}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}

export function NtaSection() {
  const query = createLiveQuery({ topics: ["dns"], fetch: (signal) => listNtas(signal).then((page) => ({ value: page.items, revision: page.revision })) });
  const [dialog, setDialog] = createSignal<{ kind: "add" } | { kind: "delete"; nta: NtaItem } | null>(null);
  // The clock the expiries are shown against, a tick a second.
  const [now, setNow] = createSignal(Date.now());
  const timer = setInterval(() => setNow(Date.now()), 1000);
  onCleanup(() => clearInterval(timer));
  const ntas = () => latest(query);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };
  return (
    <section class="page-section rec-ntas" aria-labelledby="dns-recursion-ntas-title" data-testid="dns-recursion-ntas">
      <div class="rec-status-head">
        <h2 id="dns-recursion-ntas-title">{t("dns.recursion.ntas.title")}</h2>
        <Show when={mayKeys() && !query.value.error}>
          <button type="button" class="btn" data-testid="dns-nta-add" onClick={() => setDialog({ kind: "add" })}>
            {t("dns.nta.add")}
          </button>
        </Show>
      </div>
      <p class="muted">{t("dns.nta.lede")}</p>
      <Show when={query.value.error}>
        <Show when={moduleOff(query.value.error)} fallback={<ErrorNotice error={query.value.error} />}>
          <DnsProblem error={query.value.error} />
        </Show>
      </Show>
      <Show when={ntas()}>
        {(list) => (
          <Show
            when={list().length > 0}
            fallback={
              <p class="muted" data-testid="dns-nta-none">
                {t("dns.nta.none")}
              </p>
            }
          >
            <div class="table-wrap">
              <table class="plain rec-table" data-testid="dns-nta-table">
                <caption class="sr-only">{t("dns.recursion.ntas.title")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("dns.nta.col.zone")}</th>
                    <th scope="col">{t("dns.nta.col.expires")}</th>
                    <th scope="col">{t("dns.nta.col.reason")}</th>
                    <th scope="col">{t("dns.nta.col.created")}</th>
                    <Show when={mayKeys()}>
                      <th scope="col">
                        <span class="sr-only">{t("dns.nta.col.actions")}</span>
                      </th>
                    </Show>
                  </tr>
                </thead>
                <tbody>
                  <For each={list()}>
                    {(nta) => (
                      <tr data-testid="dns-nta" data-key={nta.zone} data-id={nta.id} data-state={ntaExpired(nta, now()) ? "expired" : "active"}>
                        <td class="mono">{nta.zone}</td>
                        <td class="nowrap" data-testid="dns-nta-expires" title={formatDateTime(nta.expires_at)}>
                          <Show
                            when={!ntaExpired(nta, now())}
                            fallback={
                              <span class="tag discrepancy" data-testid="dns-nta-expired">
                                {t("dns.nta.expired")}
                              </span>
                            }
                          >
                            {formatRelative(nta.expires_at, now())}
                          </Show>
                        </td>
                        <td>{nta.reason}</td>
                        <td class="nowrap muted">{formatDateTime(nta.created_at)}</td>
                        <Show when={mayKeys()}>
                          <td class="r">
                            <button type="button" class="btn sm danger" data-testid="dns-nta-delete" onClick={() => setDialog({ kind: "delete", nta })}>
                              {t("dns.nta.delete")}
                            </button>
                          </td>
                        </Show>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        )}
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "add" ? (
            <NtaDialog onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <DeleteNtaDialog nta={d.nta} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </section>
  );
}
