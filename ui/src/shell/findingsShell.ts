// What the shell needs of the findings, in one chunk loaded after the shell is up (the first page
// load stays small; the counts come from a read anyway): the store, the rail badges and the
// status bar item.
export { useFindingCounts } from "./findings";
export { default as FindingsStatus } from "./FindingsStatus";
export { RailBadgeView, railBadge } from "./railBadge";
