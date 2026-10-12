// The dialogs of the cluster page (docs/cluster.md, section 12.3): promoting a learner,
// removing a member and handing leadership over. Each shows the preview of the change first
// (the voters and the failures the cluster tolerates before and after, the refusals the server
// would give and what the person should know) and sends nothing until the person confirms.
// The previews are computed from the view the page holds, so they follow a live change.
import { createMemo, createSignal, For, Show, type JSX } from "solid-js";
import { Dialog } from "../components/Dialog";
import { ErrorNotice, Notice } from "../components/Notice";
import { t } from "../i18n";
import { Field, SelectInput } from "../ipam/formKit";
import { promoteMember, removeMember, stepDown } from "./api";
import {
  blockerText,
  caveatText,
  memberName,
  promotePreview,
  removePreview,
  stepDownPreview,
  voters,
  type ChangePreview,
  type ClusterView,
  type MemberView,
  type StepDown,
} from "./model";
import "./cluster.css";

/** Before and after, or the one figure when the change leaves it as it is. */
function figure(before: number, after: number): string {
  return before === after ? t("cluster.preview.same", { count: before }) : t("cluster.preview.change", { before, after });
}

/** The reviewable part of a preview: the figures, the refusals and the notes. */
function PreviewBody(props: { preview: ChangePreview; children?: JSX.Element }) {
  const p = () => props.preview;
  return (
    <div class="cluster-preview" data-testid="preview">
      <dl class="cluster-figures">
        <div>
          <dt>{t("cluster.preview.voters")}</dt>
          <dd data-testid="preview-voters" data-before={p().votersBefore} data-after={p().votersAfter}>
            {figure(p().votersBefore, p().votersAfter)}
          </dd>
        </div>
        <div>
          <dt>{t("cluster.preview.tolerated")}</dt>
          <dd data-testid="preview-tolerated" data-before={p().toleratedBefore} data-after={p().toleratedAfter}>
            {figure(p().toleratedBefore, p().toleratedAfter)}
          </dd>
        </div>
      </dl>
      <Show when={p().blockers.length > 0}>
        <Notice kind="bad" title={t("cluster.preview.blockers")} testid="preview-blockers">
          <ul class="cluster-list">
            <For each={p().blockers}>{(b) => <li data-blocker={b}>{blockerText(b)}</li>}</For>
          </ul>
        </Notice>
      </Show>
      <Show when={p().forceable.length > 0}>
        <Notice kind="warn" title={t("cluster.preview.forceable")} testid="preview-forceable">
          <ul class="cluster-list">
            <For each={p().forceable}>{(b) => <li data-blocker={b}>{blockerText(b)}</li>}</For>
          </ul>
        </Notice>
      </Show>
      {props.children}
      <Show when={p().caveats.length > 0}>
        <Notice kind="warn" title={t("cluster.preview.caveats")} testid="preview-caveats">
          <ul class="cluster-list">
            <For each={p().caveats}>{(c) => <li data-caveat={c}>{caveatText(c)}</li>}</For>
          </ul>
        </Notice>
      </Show>
    </div>
  );
}

/** The buttons every dialog ends with; `confirm` stays disabled while the preview refuses. */
function Actions(props: {
  confirm: string;
  testid: string;
  danger?: boolean;
  disabled: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <div class="dialog-actions">
      <button type="button" class="btn ghost" onClick={() => props.onClose()}>
        {t("common.action.cancel")}
      </button>
      <button type="button" class={props.danger ? "btn danger" : "btn primary"} disabled={props.disabled} data-testid={props.testid} onClick={() => props.onConfirm()}>
        {props.confirm}
      </button>
    </div>
  );
}

/** Runs one request at a time and keeps its error for the dialog. */
function createSender() {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const send = async <T,>(call: () => Promise<T>): Promise<T | undefined> => {
    if (busy()) return undefined;
    setBusy(true);
    setError(null);
    try {
      return await call();
    } catch (err) {
      setError(err);
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, send };
}

/**
 * Promotes a learner to a voter. A refusal that nothing overrides disables the confirm button; one
 * that "force" overrides needs the check box; a replacement removes a voter in the same change.
 */
export function PromoteDialog(props: { view: () => ClusterView; member: MemberView; onDone: (view: ClusterView) => void; onClose: () => void }) {
  const [force, setForce] = createSignal(false);
  const [replace, setReplace] = createSignal("");
  const { busy, error, send } = createSender();
  const name = () => memberName(props.member);

  const replacing = () => (replace() === "" ? null : Number(replace()));
  const preview = createMemo(() => promotePreview(props.view(), props.member.node, { force: force(), replace: replacing() }));
  // What the rules say without "force": the check box shows while it matters, also once checked.
  const unforced = createMemo(() => promotePreview(props.view(), props.member.node, { replace: replacing() }));
  const candidates = () => voters(props.view()).filter((m) => !m.leader);
  const refused = () => preview().blockers.length > 0 || preview().forceable.length > 0;

  const confirm = async () => {
    const request: { force?: boolean; replace?: number } = {};
    if (force()) request.force = true;
    const target = replacing();
    if (target != null) request.replace = target;
    const node = props.member.node;
    const answer = await send(() => promoteMember(node, request));
    if (answer) props.onDone(answer);
  };

  return (
    <Dialog label={t("cluster.promote.title", { name: name() })} onClose={props.onClose} class="dialog cluster-dialog" testid="dialog-promote">
      <h2 class="dialog-title">{t("cluster.promote.title", { name: name() })}</h2>
      <p class="muted">{t("cluster.promote.intro")}</p>
      <PreviewBody preview={preview()}>
        <Show when={candidates().length > 0}>
          <Field name="replace" label={t("cluster.promote.replace")} help={t("cluster.promote.replace_help")}>
            {(c) => (
              <SelectInput
                {...c}
                value={replace()}
                options={[{ value: "", label: t("cluster.promote.replace_none") }, ...candidates().map((m) => ({ value: String(m.node), label: memberName(m) }))]}
                onChange={setReplace}
              />
            )}
          </Field>
        </Show>
        <Show when={unforced().forceable.length > 0}>
          <label class="check-row cluster-force">
            <input type="checkbox" class="cb" checked={force()} data-testid="field-force" onChange={(e) => setForce(e.currentTarget.checked)} />
            <span>
              {t("cluster.promote.force")}
              <small class="help">{t("cluster.promote.force_help")}</small>
            </span>
          </label>
        </Show>
      </PreviewBody>
      <ErrorNotice error={error()} />
      <Actions confirm={t("cluster.promote.confirm")} testid="promote-confirm" disabled={busy() || refused()} onConfirm={() => void confirm()} onClose={props.onClose} />
    </Dialog>
  );
}

/** Removes a member from the cluster; its certificates are revoked, so this asks plainly. */
export function RemoveDialog(props: { view: () => ClusterView; member: MemberView; onDone: (view: ClusterView) => void; onClose: () => void }) {
  const { busy, error, send } = createSender();
  const name = () => memberName(props.member);
  const preview = createMemo(() => removePreview(props.view(), props.member.node));

  const confirm = async () => {
    const node = props.member.node;
    const answer = await send(() => removeMember(node));
    if (answer) props.onDone(answer);
  };

  return (
    <Dialog label={t("cluster.remove.title", { name: name() })} onClose={props.onClose} class="dialog cluster-dialog" testid="dialog-remove">
      <h2 class="dialog-title">{t("cluster.remove.title", { name: name() })}</h2>
      <p class="muted">{t("cluster.remove.intro")}</p>
      <PreviewBody preview={preview()} />
      <ErrorNotice error={error()} />
      <Actions
        confirm={t("cluster.remove.confirm")}
        testid="remove-confirm"
        danger
        disabled={busy() || preview().blockers.length > 0}
        onConfirm={() => void confirm()}
        onClose={props.onClose}
      />
    </Dialog>
  );
}

/** Hands leadership to the most caught-up other voter; this controller stays a voter. */
export function StepDownDialog(props: { view: () => ClusterView; onDone: (answer: StepDown) => void; onClose: () => void }) {
  const { busy, error, send } = createSender();
  const preview = createMemo(() => stepDownPreview(props.view()));

  const confirm = async () => {
    const answer = await send(() => stepDown());
    if (answer) props.onDone(answer);
  };

  return (
    <Dialog label={t("cluster.step_down.title")} onClose={props.onClose} class="dialog cluster-dialog" testid="dialog-step-down">
      <h2 class="dialog-title">{t("cluster.step_down.title")}</h2>
      <p class="muted">{t("cluster.step_down.intro")}</p>
      <PreviewBody preview={preview()}>
        <Show when={preview().successor}>
          {(next) => (
            <p data-testid="step-down-successor" data-node={next().node}>
              {t("cluster.step_down.successor", { name: memberName(next()) })}
            </p>
          )}
        </Show>
      </PreviewBody>
      <ErrorNotice error={error()} />
      <Actions
        confirm={t("cluster.step_down.confirm")}
        testid="step-down-confirm"
        disabled={busy() || preview().blockers.length > 0}
        onConfirm={() => void confirm()}
        onClose={props.onClose}
      />
    </Dialog>
  );
}
