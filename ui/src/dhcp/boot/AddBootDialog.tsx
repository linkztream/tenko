// "Add a boot file" (docs/dhcp.md, section 16.2): a boot file for one client type of a scope. The
// client type decides the class (its matches are the architecture codes of RFC 4578, the vendor
// class HTTPClient, or the user class iPXE); the dialog reuses a class with exactly those matches
// or creates one, creates the policy of the scope over that class, and sets option 67 on the
// policy. The steps run in that order and a failure says which of them was done: a retry goes on
// where the dialog stopped instead of making the same class or policy twice.
import { createSignal, For, Show } from "solid-js";
import { ApiError, errorMessage } from "../../api/problem";
import { Dialog } from "../../components/Dialog";
import { ErrorNotice, Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { createClass, createPolicy, putOptionSet, type DhcpClass, type Policy, type Scope } from "../api";
import { matchesWords } from "../words";
import { BOOT_CODE, BOOT_KINDS, checkBootFile, ipxeOrder, ipxeTies, kindMatches, kindName, sameMatches, uniqueName, type BootKind } from "./model";

/** The words for a client type. */
function kindWord(kind: BootKind): string {
  switch (kind) {
    case "bios":
      return t("dhcp.boot.kind.bios");
    case "uefi-x64":
      return t("dhcp.boot.kind.uefi_x64");
    case "uefi-arm64":
      return t("dhcp.boot.kind.uefi_arm64");
    case "http-x64":
      return t("dhcp.boot.kind.http_x64");
    case "http":
      return t("dhcp.boot.kind.http");
    case "ipxe":
      return t("dhcp.boot.kind.ipxe");
  }
}

export function AddBootDialog(props: {
  scope: Scope;
  /** Every class, to reuse one with the same matches and to keep the new name free. */
  classes: readonly DhcpClass[];
  /** The policies of this scope, for the name and the order of the new one. */
  policies: readonly Policy[];
  onClose: () => void;
  onDone: () => void;
}) {
  let kindSelect!: HTMLSelectElement;
  const [kind, setKind] = createSignal<BootKind>("bios");
  const [file, setFile] = createSignal("");
  const [fileError, setFileError] = createSignal<string | undefined>();
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  // Set when a step failed, so that what the steps before it made is told once nothing runs any more.
  const [failed, setFailed] = createSignal(false);
  // What the steps made so far: a retry does not make it again.
  const [madeClass, setMadeClass] = createSignal<DhcpClass | undefined>();
  const [madePolicy, setMadePolicy] = createSignal<Policy | undefined>();

  const orders = () => props.policies.map((p) => p.order);

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const problem = checkBootFile(file());
    setFileError(problem === null ? undefined : problem === "empty" ? t("dhcp.boot.check.file_empty") : t("dhcp.boot.check.long"));
    if (problem !== null) return;
    setBusy(true);
    setError(undefined);
    setFailed(false);
    const chosen = kind();
    try {
      const matches = kindMatches(chosen);
      let cls = madeClass() ?? props.classes.find((c) => sameMatches(c.matches, matches));
      if (!cls) {
        cls = await createClass({
          name: uniqueName(kindName(chosen), new Set(props.classes.map((c) => c.name))),
          matches,
        });
        setMadeClass(cls);
      }
      let policy = madePolicy();
      if (!policy) {
        policy = await createPolicy({
          name: uniqueName(kindName(chosen), new Set(props.policies.map((p) => p.name))),
          scope: props.scope.prefix,
          ...(chosen === "ipxe" ? { order: ipxeOrder(orders()) } : {}),
          enabled: true,
          condition: { join: "or", terms: [{ class: cls.id }] },
          action: {},
        });
        setMadePolicy(policy);
      }
      await putOptionSet({ path: `policy:${policy.id}`, revision: 0 }, [{ code: BOOT_CODE.file, typed: { text: file().trim() } }]);
      toast({ kind: "ok", title: t("dhcp.boot.add_done", { name: policy.name }) });
      props.onDone();
    } catch (err) {
      setFailed(true);
      if (err instanceof ApiError && err.params.code === String(BOOT_CODE.file) && madePolicy()) setFileError(errorMessage(err));
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("dhcp.boot.add_title")} onClose={props.onClose} class="dialog dhcp-dialog" testid="dialog-boot-add" initialFocus={() => kindSelect}>
      <h2 class="dialog-title">{t("dhcp.boot.add_title")}</h2>
      <form class="dialog-body dhcp-form" onSubmit={(e) => void submit(e)} novalidate>
        <div class="field">
          <label for="dhcp-f-boot-kind">{t("dhcp.boot.add_kind")}</label>
          <select
            ref={kindSelect}
            id="dhcp-f-boot-kind"
            class="select"
            value={kind()}
            disabled={madeClass() !== undefined || madePolicy() !== undefined}
            aria-describedby="dhcp-f-boot-kind-help"
            data-testid="field-boot-kind"
            onChange={(e) => setKind(e.currentTarget.value as BootKind)}
          >
            <For each={BOOT_KINDS}>{(k) => <option value={k}>{kindWord(k)}</option>}</For>
          </select>
          <span class="help" id="dhcp-f-boot-kind-help" data-testid="boot-add-matches">
            {t("dhcp.boot.add_matches", { words: matchesWords(kindMatches(kind())) })}
          </span>
        </div>
        <div class="field">
          <label for="dhcp-f-boot-add-file">{t("dhcp.boot.add_file")}</label>
          <input
            id="dhcp-f-boot-add-file"
            class="input mono"
            value={file()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={fileError() ? "true" : undefined}
            aria-describedby="dhcp-f-boot-add-file-help"
            data-testid="field-boot-add-file"
            onInput={(e) => setFile(e.currentTarget.value)}
          />
          <Show when={fileError()}>
            <span class="help bad" data-testid="field-error" data-field="boot-add-file">
              {fileError()}
            </span>
          </Show>
          <span class="help" id="dhcp-f-boot-add-file-help">
            {t("dhcp.boot.add_file_help")}
          </span>
        </div>
        <p class="muted" data-testid="boot-add-order-help">
          {kind() === "ipxe" ? (ipxeTies(orders()) ? t("dhcp.boot.add_order_tie") : t("dhcp.boot.add_order_first")) : t("dhcp.boot.add_order_last")}
        </p>
        <Show when={failed() && (madePolicy() ?? madeClass())}>
          <Notice kind="warn" role="status" testid="boot-add-partial">
            {madePolicy() ? t("dhcp.boot.add_partial_policy", { policy: madePolicy()?.name ?? "" }) : t("dhcp.boot.add_partial_class", { class: madeClass()?.name ?? "" })}
          </Notice>
        </Show>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dhcp.boot.add_submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
