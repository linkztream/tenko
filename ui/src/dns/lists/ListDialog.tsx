// The dialogs of a block list: create and edit (name, a URL or an upload as the source, the
// file format, how often a URL list is fetched, what a blocked name answers, whether the list
// is applied, the description; a new uploaded list may take its file at once), the upload of
// a file into an uploaded list (the page follows the job that compiles it), and delete. The form checks what it can before it sends; a
// refusal of the server (`dns.list.invalid` with `field`) lands under the field it names.
import { createSignal, For, Show, untrack } from "solid-js";
import { ApiError } from "../../api/problem";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { describedBy, Field } from "../Parts";
import { uploadBlockList } from "../api";
import { createBlockList, deleteBlockList, updateBlockList, type BlockListItem } from "./api";
import { ACTIONS, checkList, draftOf, FORMATS, MAX_INTERVAL, MIN_INTERVAL, type ListDraft, type ListProblem } from "./model";

function problemText(p: ListProblem): string {
  switch (p) {
    case "name":
      return t("dns.list.check.name");
    case "url":
      return t("dns.list.check.url");
    case "interval":
      return t("dns.list.check.interval", { min: MIN_INTERVAL, max: MAX_INTERVAL });
    case "redirect":
      return t("dns.list.check.redirect");
  }
}

/** The form field a refusal of the server names. */
function refusedField(err: unknown): string | undefined {
  if (!(err instanceof ApiError)) return undefined;
  const field = err.code === "dns.list.invalid" ? err.params.field : err.code === "sys.invalid_value" ? err.params.name : undefined;
  if (!field) return undefined;
  if (field === "source" || field.startsWith("source.")) return "url";
  if (field === "interval_hours") return "interval";
  if (field === "action" || field.startsWith("action.")) return "redirect";
  return field;
}

/** The file chooser of an uploaded list (text in the hosts or domains format). */
function FileField(props: { file: File | null; onFile: (file: File | null) => void; error?: string | undefined }) {
  const help = () => (props.file ? t("dns.list.file_chosen", { name: props.file.name }) : t("dns.list.field.file_help"));
  return (
    <Field id="file" label={t("dns.list.field.file")} error={props.error} help={help()}>
      <input
        id="dns-f-file"
        class="input"
        type="file"
        accept=".txt,.list,.hosts,text/plain"
        aria-invalid={props.error ? "true" : undefined}
        aria-describedby={describedBy("file", props.error, "help")}
        data-testid="field-file"
        onChange={(ev) => props.onFile(ev.currentTarget.files?.[0] ?? null)}
      />
    </Field>
  );
}

export function ListDialog(props: { list?: BlockListItem; onClose: () => void; onDone: (job?: { id: string; name: string }) => void }) {
  let nameInput!: HTMLInputElement;
  const list = untrack(() => props.list);
  const [draft, setDraft] = createSignal<ListDraft>(draftOf(list));
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const [file, setFile] = createSignal<File | null>(null);
  const set = <K extends keyof ListDraft>(key: K, value: ListDraft[K]) => setDraft({ ...draft(), [key]: value });

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const checked = checkList(draft());
    if (!checked.ok) {
      const e: Record<string, string> = {};
      for (const p of checked.problems) e[p] = problemText(p);
      setErrors(e);
      return;
    }
    setErrors({});
    setBusy(true);
    setError(undefined);
    try {
      if (list) {
        await updateBlockList(list, { ...checked.body, description: checked.body.description ?? "" });
        toast({ kind: "ok", title: t("dns.list.saved", { name: checked.body.name }) });
      } else {
        const made = await createBlockList(checked.body);
        toast({ kind: "ok", title: t("dns.list.created", { name: checked.body.name }) });
        const chosen = draft().source === "upload" ? file() : null;
        if (chosen) {
          props.onDone({ id: await uploadBlockList(made, await chosen.text()), name: made.name });
          return;
        }
      }
      props.onDone();
    } catch (err) {
      const field = refusedField(err);
      if (field) setErrors({ [field]: t("errors.dns.list.invalid") });
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const text = (id: "name" | "url" | "interval" | "redirect" | "description", key: keyof ListDraft, label: string, help?: string, mono = true) => (
    <Field id={id} label={label} error={errors()[id]} help={help}>
      <input
        ref={id === "name" ? nameInput : undefined}
        id={`dns-f-${id}`}
        class={mono ? "input mono" : "input"}
        value={String(draft()[key])}
        spellcheck={false}
        autocomplete="off"
        inputmode={id === "interval" ? "numeric" : undefined}
        aria-invalid={errors()[id] ? "true" : undefined}
        aria-describedby={describedBy(id, errors()[id], help)}
        data-testid={`field-${id}`}
        onInput={(ev) => set(key, ev.currentTarget.value as never)}
      />
    </Field>
  );

  const title = () => (list ? t("dns.list.edit_title", { name: list.name }) : t("dns.list.create_title"));
  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog wide dns-dialog" testid="dialog-list-form" initialFocus={() => nameInput}>
      <h2 class="dialog-title">{title()}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        {text("name", "name", t("dns.list.field.name"), undefined, false)}
        <fieldset class="dns-modes">
          <legend>{t("dns.list.field.source")}</legend>
          <For each={["url", "upload"] as const}>
            {(kind) => (
              <label class="choice">
                <input
                  type="radio"
                  name="dns-list-source"
                  checked={draft().source === kind}
                  disabled={!!list && list.source.kind !== kind}
                  data-testid={`field-source-${kind}`}
                  onChange={() => set("source", kind)}
                />
                <span>{t(`dns.list.source.${kind}`)}</span>
              </label>
            )}
          </For>
        </fieldset>
        <Show
          when={draft().source === "url"}
          fallback={
            <Show when={!list} fallback={<p class="muted">{t("dns.list.upload_hint")}</p>}>
              <FileField file={file()} onFile={setFile} />
            </Show>
          }
        >
          {text("url", "url", t("dns.list.field.url"), t("dns.list.field.url_help"))}
          {text("interval", "interval", t("dns.list.field.interval"), t("dns.list.field.interval_help", { min: MIN_INTERVAL, max: MAX_INTERVAL }))}
        </Show>
        <div class="field-row">
          <Field id="format" label={t("dns.list.field.format")} help={t(`dns.list.format.${draft().format}_help`)}>
            <select
              id="dns-f-format"
              class="select"
              value={draft().format}
              data-testid="field-format"
              aria-describedby="dns-f-format-help"
              onChange={(e) => set("format", e.currentTarget.value as ListDraft["format"])}
            >
              <For each={FORMATS}>{(f) => <option value={f}>{t(`dns.list.format.${f}`)}</option>}</For>
            </select>
          </Field>
          <Field id="action" label={t("dns.list.field.action")}>
            <select id="dns-f-action" class="select" value={draft().action} data-testid="field-action" onChange={(e) => set("action", e.currentTarget.value as ListDraft["action"])}>
              <For each={ACTIONS}>{(a) => <option value={a}>{t(`dns.list.action.${a}`)}</option>}</For>
            </select>
          </Field>
        </div>
        <Show when={draft().action === "redirect"}>{text("redirect", "redirect", t("dns.list.field.redirect"), t("dns.list.field.redirect_help"))}</Show>
        <div class="field">
          <label class="choice">
            <input type="checkbox" checked={draft().enabled} data-testid="field-enabled" onChange={(e) => set("enabled", e.currentTarget.checked)} />
            <span>{t("dns.list.field.enabled")}</span>
          </label>
        </div>
        {text("description", "description", t("dns.zone.field.description"), undefined, false)}
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {list ? t("dns.list.save") : t("dns.list.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function UploadListDialog(props: { list: BlockListItem; onClose: () => void; onDone: (job: string) => void }) {
  const [file, setFile] = createSignal<File | null>(null);
  const [problem, setProblem] = createSignal<string>();
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const chosen = file();
    if (!chosen) {
      setProblem(t("dns.list.check.file"));
      return;
    }
    setProblem(undefined);
    setBusy(true);
    setError(undefined);
    try {
      const job = await uploadBlockList(props.list, await chosen.text());
      toast({ kind: "ok", title: t("dns.list.uploaded", { name: props.list.name }) });
      props.onDone(job);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  const title = () => t("dns.list.upload_title", { name: props.list.name });
  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog dns-dialog" testid="dialog-list-upload">
      <h2 class="dialog-title">{title()}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        <p>{t(`dns.list.format.${props.list.format}_help`)}</p>
        <FileField file={file()} onFile={setFile} error={problem()} />
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dns.list.upload")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function DeleteListDialog(props: { list: BlockListItem; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dns.list.delete_title", { name: props.list.name })}
      testid="dialog-list-delete"
      danger
      busy={busy()}
      confirmLabel={t("dns.list.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteBlockList(props.list)
          .then(() => {
            toast({ kind: "ok", title: t("dns.list.deleted", { name: props.list.name }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dns.list.delete_body")}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}
