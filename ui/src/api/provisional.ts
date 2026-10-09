// Typed overlay for operations that are still stubs in the OpenAPI document. Keys are
// "<method> <path>" exactly as in the document, values are types from ./types. The client
// uses an entry only while the document has no schema for that response or body; the
// moment it has one, the generated type wins and `StaleProvisional` in client.ts names the
// entry to delete (the type check fails until it is gone).
//
// Every operation the UI of Slice 1 calls is described by the document now, so both maps
// are empty. Add an entry when a view needs an operation before the backend describes it:
//
//   "get /api/v1/prefixes/tree": T.TreeProvisional;
// eslint-disable-next-line @typescript-eslint/no-empty-object-type -- filled while stubs exist
export interface ProvisionalResponses {}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type -- filled while stubs exist
export interface ProvisionalBodies {}
