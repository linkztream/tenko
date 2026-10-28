// The cards behind the chips of the top bar, in one lazily loaded chunk: the cluster card of the
// node chip and the profile card of the profile chip. One is open at a time.
import { Show } from "solid-js";
import type { Profile, SystemStatus } from "../api/types";
import type { ClusterSummary } from "./cluster";
import ClusterCard from "./ClusterCard";
import ProfileCard from "./ProfileCard";

export default function TopCards(props: {
  kind: "cluster" | "profile";
  id: string;
  anchor: HTMLElement;
  system: SystemStatus | null;
  summary: ClusterSummary;
  profile: Profile;
  onClose: () => void;
}) {
  return (
    <Show when={props.kind === "cluster"} fallback={<ProfileCard id={props.id} anchor={props.anchor} profile={props.profile} onClose={props.onClose} />}>
      <ClusterCard id={props.id} anchor={props.anchor} system={props.system} summary={props.summary} onClose={props.onClose} />
    </Show>
  );
}
