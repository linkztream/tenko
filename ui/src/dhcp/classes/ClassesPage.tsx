// The client classes (/dhcp/classes): a class is a name for clients recognised by what they send;
// it holds when any of its matches holds. A row has the name, the matches in words, the number of
// scopes, pools and policies that name it, and the description. Create and edit with the match
// editor, delete; a class that is named is not deleted, and the confirmation shows the server's
// message.
import { createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { DataGrid } from "../../grid/DataGrid";
import type { Column, RowAction } from "../../grid/types";
import { formatNumber, t } from "../../i18n";
import { mayWriteDhcp } from "../access";
import { createClass, deleteClass, listClasses, updateClass, type DhcpClass, type Match } from "../api";
import { DhcpNav } from "../DhcpNav";
import { draftOfMatch, emptyMatch, matchOfDraft, validDhcpName, type MatchDraft } from "../model";
import { describedBy, DhcpProblem, errorFor, Field, fieldErrors, hasField, unavailable } from "../Parts";
import { matchesWords, matchWords } from "../words";
import { MatchList, matchProblem } from "./MatchEditor";
import "../dhcp.css";

function ClassDialog(props: { item?: DhcpClass; onClose: () => void; onDone: () => void }) {
  let nameInput!: HTMLInputElement;
  const item = untrack(() => props.item);
  const [name, setName] = createSignal(item?.name ?? "");
  const [description, setDescription] = createSignal(item?.description ?? "");
  const [matches, setMatches] = createSignal<MatchDraft[]>(item ? item.matches.map(draftOfMatch) : [emptyMatch()]);
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [matchErrors, setMatchErrors] = createSignal<Record<number, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    const me: Record<number, string> = {};
    if (!validDhcpName(name().trim())) e.name = t("dhcp.check.name");
    const built: Match[] = [];
    matches().forEach((draft, i) => {
      const parsed = matchOfDraft(draft);
      if (parsed.ok) built.push(parsed.match);
      else me[i] = matchProblem(parsed.problem);
    });
    setErrors(e);
    setMatchErrors(me);
    if (Object.keys(e).length > 0 || Object.keys(me).length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      const text = description().trim();
      if (item) await updateClass(item, { name: name().trim(), matches: built, description: text });
      else await createClass({ name: name().trim(), matches: built, ...(text !== "" ? { description: text } : {}) });
      toast({ kind: "ok", title: item ? t("dhcp.class.saved", { name: name().trim() }) : t("dhcp.class.created", { name: name().trim() }) });
      props.onDone();
    } catch (err) {
      const fields = fieldErrors(err);
      const named = Object.keys(fields);
      if (hasField(fields, ["name", "matches"])) {
        setErrors(fields);
        // `matches[2]` names the third row.
        const rows: Record<number, string> = {};
        for (const key of named) {
          const m = /^matches\[(\d+)\]/.exec(key);
          if (m) rows[Number(m[1])] = fields[key] ?? "";
        }
        setMatchErrors(rows);
      } else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const title = () => (item ? t("dhcp.class.edit_title", { name: item.name }) : t("dhcp.class.create_title"));
  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog wide dhcp-dialog" testid="dialog-class-form" initialFocus={() => nameInput}>
      <h2 class="dialog-title">{title()}</h2>
      <form class="dialog-body dhcp-form" onSubmit={(ev) => void submit(ev)} novalidate>
        <Field id="name" label={t("dhcp.class.field.name")} error={errorFor(errors(), "name")} help={t("dhcp.field.name_help")}>
          <input
            ref={nameInput}
            id="dhcp-f-name"
            class="input mono"
            value={name()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().name ? "true" : undefined}
            aria-describedby={describedBy("name", errors().name, "help")}
            data-testid="field-name"
            onInput={(ev) => setName(ev.currentTarget.value)}
          />
        </Field>
        <fieldset class="dhcp-matches-field">
          <legend>{t("dhcp.class.field.matches")}</legend>
          <p class="muted">{t("dhcp.class.field.matches_help")}</p>
          <MatchList value={matches()} onChange={setMatches} errors={matchErrors()} />
          <Show when={errors().matches}>
            <span class="help bad" data-testid="field-error" data-field="matches">
              {errors().matches}
            </span>
          </Show>
        </fieldset>
        <Field id="description" label={t("dhcp.field.description")}>
          <input id="dhcp-f-description" class="input" value={description()} data-testid="field-description" onInput={(ev) => setDescription(ev.currentTarget.value)} />
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {item ? t("dhcp.class.save") : t("dhcp.class.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteClassDialog(props: { item: DhcpClass; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dhcp.class.delete_title", { name: props.item.name })}
      testid="dialog-class-delete"
      danger
      busy={busy()}
      confirmLabel={t("dhcp.class.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteClass(props.item)
          .then(() => {
            toast({ kind: "ok", title: t("dhcp.class.deleted", { name: props.item.name }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dhcp.class.delete_body")}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}

export default function ClassesPage() {
  const [dialog, setDialog] = createSignal<{ kind: "edit"; item?: DhcpClass } | { kind: "delete"; item: DhcpClass } | null>(null);
  const query = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const page = await listClasses(signal);
      return { value: page.items, revision: page.revision };
    },
  });
  const blocked = () => unavailable(query.value.error);
  const classes = () => latest(query);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };

  const columns: Column<DhcpClass>[] = [
    { id: "name", header: () => t("dhcp.col.name"), width: 200, fixed: true, text: (c) => c.name, render: (c) => <span class="mono">{c.name}</span> },
    {
      id: "matches",
      header: () => t("dhcp.col.matches"),
      text: (c) => matchesWords(c.matches),
      render: (c) => (
        <span class="dhcp-chips">
          <For each={c.matches}>
            {(m) => (
              <span class="tag" data-testid="class-match">
                {matchWords(m)}
              </span>
            )}
          </For>
        </span>
      ),
    },
    { id: "used_by", header: () => t("dhcp.col.used_by"), width: 100, align: "right", text: (c) => String(c.used_by), render: (c) => <span class="num" data-testid="class-used-by" data-value={String(c.used_by)}>{formatNumber(c.used_by)}</span> },
    { id: "description", header: () => t("dhcp.col.description"), width: 240, render: (c) => <span class="muted">{c.description ?? ""}</span> },
  ];
  const actions: RowAction<DhcpClass>[] = [
    { id: "edit", label: () => t("dhcp.do.edit"), hidden: () => !mayWriteDhcp(), run: (c) => setDialog({ kind: "edit", item: c }) },
    { id: "delete", label: () => t("dhcp.do.delete"), danger: true, hidden: () => !mayWriteDhcp(), run: (c) => setDialog({ kind: "delete", item: c }) },
  ];

  return (
    <div class="page dhcp-page list-page" data-testid="page-dhcp-classes">
      <DhcpNav />
      <PageHead
        title={t("dhcp.classes.title")}
        sub={t("dhcp.classes.sub")}
        actions={
          <Show when={mayWriteDhcp() && !blocked()}>
            <button type="button" class="btn primary" data-testid="dhcp-class-create" onClick={() => setDialog({ kind: "edit" })}>
              <Icon name="plus" />
              {t("dhcp.class.create")}
            </button>
          </Show>
        }
      />
      <Show
        when={!blocked()}
        fallback={
          <div class="page-body">
            <DhcpProblem error={query.value.error} />
          </div>
        }
      >
        <div class="dhcp-list-body">
          <DataGrid
            id="dhcp-classes"
            label={t("dhcp.classes.title")}
            noSelection
            columns={columns}
            rows={classes() ?? []}
            rowId={(c) => c.id}
            rowKey={(c) => c.name}
            rowLabel={(c) => c.name}
            loading={query.value.loading}
            initial={classes() === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            onOpen={(c) => (mayWriteDhcp() ? setDialog({ kind: "edit", item: c }) : undefined)}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dhcp-classes-empty">
                <h3>{t("dhcp.classes.empty")}</h3>
                <p>{t("dhcp.classes.empty_body")}</p>
              </div>
            }
          />
        </div>
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "edit" ? (
            <ClassDialog item={d.item} onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <DeleteClassDialog item={d.item} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
