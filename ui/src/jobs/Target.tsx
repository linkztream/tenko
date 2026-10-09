// An object a job changes: a host by its name (read once per tab through the IPAM resolver),
// anything else by its kind and a short id.
import { A } from "@solidjs/router";
import { createResource, Show } from "solid-js";
import type { ObjectRef } from "../api/types";
import { paths } from "../app/paths";
import { shortId } from "../components/Principal";
import { tDynamic } from "../i18n";
import { readHost } from "../ipam/resolve";

/** The kind of an object in words; a kind without a word comes back as it is. */
export function kindText(kind: string): string {
  return tDynamic(`jobs.kind.${kind}`) ?? kind;
}

/** "prefix 0190d1c2": the kind in words and the start of the id. */
export function targetText(target: ObjectRef): string {
  return `${kindText(target.kind)} ${shortId(target.id)}`;
}

/** The host a job changes, when one of its targets is a host. */
export function firstHost(targets: readonly ObjectRef[]): ObjectRef | undefined {
  return targets.find((target) => target.kind === "host");
}

export function TargetLabel(props: { target: ObjectRef }) {
  const [host] = createResource(
    () => (props.target.kind === "host" ? props.target.id : false),
    (id) => readHost(id),
  );
  return (
    <Show
      when={host()}
      fallback={
        <span class="job-target" title={props.target.id}>
          {targetText(props.target)}
        </span>
      }
    >
      {(h) => (
        <A class="job-target hostname" href={paths.host(h().name)}>
          {h().name}
        </A>
      )}
    </Show>
  );
}
