// Deleting and restoring an IPAM object (IPAM-09). Both go through the plan dialog: the
// delete is previewed (what goes with it, what is refused), then applied. A delete is a soft
// delete, so its toast offers Undo, which restores the object at once.
import { createSignal, Show } from "solid-js";
import { ANY_REVISION } from "../api/client";
import { errorMessage } from "../api/problem";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { CASCADING, deleteObject, restoreObject, type Collection } from "./collections";
import { PlanDialog, useWriteToast, type WriteLike } from "./plan/PlanDialog";
import { kindWord } from "./words";
import "./forms.css";

interface Props {
  collection: Collection;
  id: string;
  /** The kind of object, for the words of the dialog: `prefix`, `address`, `range`, ... */
  kind: string;
  /** What the person knows the object by: a network, an address, a name. */
  label: string;
  /** The revision the person saw; the write is refused when the object has changed since. */
  revision?: number | null | undefined;
  onDone: (result: WriteLike) => void;
  onClose: () => void;
}

export function DeleteDialog(props: Props & { cascade?: boolean | undefined }) {
  const writeToast = useWriteToast();
  const [cascade, setCascade] = createSignal(false);
  const offered = () => !!props.cascade && CASCADING.has(props.collection);
  const words = () => ({ kind: kindWord(props.kind), label: props.label });

  const undo = async () => {
    try {
      const restored = await restoreObject(props.collection, props.id, { dryRun: false, acknowledge: [], revision: ANY_REVISION });
      writeToast(t("ipam.restore.done", words()), restored);
      props.onDone(restored);
    } catch (err) {
      toast({ kind: "bad", title: t("ipam.delete.undo_failed", words()), body: errorMessage(err) });
    }
  };

  // The preview is for one choice of the check box: a new choice is a new dialog.
  return (
    <Show when={{ cascade: cascade() }} keyed>
      {(_choice) => (
        <PlanDialog
          title={t("ipam.delete.title", words())}
          confirmLabel={t("ipam.delete.title", words())}
          danger
          testid="dialog-delete"
          intro={
            <Show when={offered()}>
              <label class="delete-cascade">
                <input
                  type="checkbox"
                  class="cb"
                  data-testid="delete-cascade"
                  checked={cascade()}
                  onChange={(e) => setCascade(e.currentTarget.checked)}
                />
                {t("ipam.delete.cascade")}
              </label>
            </Show>
          }
          send={(options) => deleteObject(props.collection, props.id, { ...options, revision: props.revision, cascade: cascade() })}
          onDone={(result) => {
            writeToast(t("ipam.delete.done", words()), result, [{ label: t("ipam.delete.undo"), run: () => void undo() }]);
            props.onDone(result);
          }}
          onClose={props.onClose}
        />
      )}
    </Show>
  );
}

export function RestoreDialog(props: Props) {
  const writeToast = useWriteToast();
  const words = () => ({ kind: kindWord(props.kind), label: props.label });
  return (
    <PlanDialog
      title={t("ipam.restore.title", words())}
      confirmLabel={t("ipam.restore.title", words())}
      testid="dialog-restore"
      send={(options) => restoreObject(props.collection, props.id, { ...options, revision: props.revision })}
      onDone={(result) => {
        writeToast(t("ipam.restore.done", words()), result);
        props.onDone(result);
      }}
      onClose={props.onClose}
    />
  );
}
