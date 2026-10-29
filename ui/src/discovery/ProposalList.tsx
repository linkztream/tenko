// The Proposals tab of Discovery (/discovery/proposals, /discovery/proposals/<id>): every
// proposal with its state, the decided ones included, filtered and sorted by the server, with the
// decisions on many at once. Since U4 the findings list is the default page of Discovery; this is
// the proposal list it was before, with its flows and their routes unchanged.
import ProposalsView from "./ProposalsView";

export default function ProposalList() {
  return <ProposalsView list />;
}
