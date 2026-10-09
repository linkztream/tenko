import { createSignal, For } from "solid-js";
import { t } from "../i18n";
import { Icon } from "./Icon";
import { toast } from "./toast";

/**
 * Recovery codes, shown once (IAM-06): download, print or copy, then confirm they are
 * saved. Used after first-run setup, after the first factor enrolment and after
 * regenerating codes. The parent gates on `onSavedChange(true)`.
 */
export function RecoveryCodes(props: {
  codes: readonly string[];
  /** Base of the download file name, for example the node or account name. */
  fileBase: string;
  saved: boolean;
  onSavedChange: (saved: boolean) => void;
}) {
  const [printing, setPrinting] = createSignal(false);
  const text = () => `${props.codes.join("\n")}\n`;

  const download = () => {
    const url = URL.createObjectURL(new Blob([text()], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${props.fileBase}-recovery-codes.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  const print = () => {
    setPrinting(true);
    // Let the print-only class apply before the dialog opens.
    requestAnimationFrame(() => {
      window.print();
      setPrinting(false);
    });
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text());
      toast({ title: t("recovery.copied"), kind: "ok" });
    } catch {
      toast({ title: t("recovery.copy_failed"), kind: "bad" });
    }
  };

  return (
    <div class="recovery">
      <div classList={{ "print-area": printing() }}>
        <ol class="codes" aria-label={t("recovery.list_label")}>
          <For each={props.codes}>{(code) => <li>{code}</li>}</For>
        </ol>
      </div>
      <div class="form-row recovery-actions">
        <button type="button" class="btn" onClick={download}>
          <Icon name="download" size="sm" />
          {t("recovery.download")}
        </button>
        <button type="button" class="btn" onClick={print}>
          <Icon name="print" size="sm" />
          {t("recovery.print")}
        </button>
        <button type="button" class="btn ghost" onClick={() => void copy()}>
          <Icon name="copy" size="sm" />
          {t("common.action.copy")}
        </button>
      </div>
      <label class="ackrow">
        <input
          type="checkbox"
          class="cb"
          checked={props.saved}
          onChange={(e) => props.onSavedChange(e.currentTarget.checked)}
        />
        {t("recovery.saved")}
      </label>
    </div>
  );
}
