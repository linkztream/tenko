import { describe, expect, it } from "vitest";
import type { AuditRecord } from "../api/types";
import { isZeroHash, principalSubject, shortHash } from "./model";
import { objectFilter, objectLabel, objectViews } from "./objects";

const A = "0190d1c2-0000-7000-8000-0000000b0001";
const B = "0190d1c2-0000-7000-8000-0000000b0002";
const C = "0190d1c2-0000-7000-8000-0000000c0001";

function record(action: string, objects: AuditRecord["draft"]["objects"], changes: NonNullable<AuditRecord["draft"]["details"]>["changes"]) {
  return { draft: { action, outcome: { kind: "success" as const }, objects, details: { changes } } };
}

describe("labels and links of the objects of a record", () => {
  it("labels and links a host, a prefix and an address from the changes that name them", () => {
    const host = record("ipam.host.create", [{ kind: "host", id: A }], [{ field: "name", old: null, new: "nas.example.test" }]);
    expect(objectViews(host)).toEqual([
      { ref: { kind: "host", id: A }, text: "nas.example.test", labeled: true, href: "/ipam/hosts/nas.example.test" },
    ]);
    const prefix = record("ipam.prefix.update", [{ kind: "prefix", id: A }], [{ field: "cidr", old: "198.51.100.0/24", new: null }]);
    expect(objectViews(prefix)[0]?.href).toBe("/ipam/prefixes/198.51.100.0/24");
    const address = record("ipam.address.create", [{ kind: "address", id: A }], [{ field: "ip", old: null, new: "2001:db8::1" }]);
    expect(objectViews(address)[0]?.href).toBe("/ipam/addresses/2001:db8::1");
  });

  it("links a job by its id", () => {
    const job = record("jobs.job.cancel", [{ kind: "job", id: C }], []);
    expect(objectViews(job)[0]).toEqual({ ref: { kind: "job", id: C }, text: "0190d1c2", labeled: false, href: `/jobs/${C}` });
  });

  it("shows other kinds, and objects the changes do not name, as kind and short id without a link", () => {
    const user = record("users.user.update", [{ kind: "user", id: A }], [{ field: "name", old: "a", new: "b" }]);
    expect(objectViews(user)[0]).toMatchObject({ text: "0190d1c2", labeled: false, href: undefined });
    const host = record("ipam.host.update", [{ kind: "host", id: A }], [{ field: "mode", old: "static", new: "reserved" }]);
    expect(objectViews(host)[0]).toMatchObject({ text: "0190d1c2", href: undefined });
  });

  it("names a deleted object but does not link it", () => {
    const gone = record("ipam.address.delete", [{ kind: "address", id: A }], [{ field: "ip", old: "192.0.2.35", new: null }]);
    expect(objectViews(gone)[0]).toMatchObject({ text: "192.0.2.35", labeled: true, href: undefined });
  });

  it("uses the object of a change when the record names several of one kind", () => {
    const two = record(
      "ipam.host.update",
      [
        { kind: "host", id: A },
        { kind: "host", id: B },
      ],
      [
        { field: "name", old: "a.example.test", new: "a2.example.test", object: { kind: "host", id: A } },
        { field: "name", old: "b.example.test", new: "b2.example.test", object: { kind: "host", id: B } },
      ],
    );
    expect(objectViews(two).map((o) => o.text)).toEqual(["a2.example.test", "b2.example.test"]);
    // Changes that name no object are ambiguous here: no label.
    const unnamed = record(
      "ipam.host.update",
      [
        { kind: "host", id: A },
        { kind: "host", id: B },
      ],
      [{ field: "name", old: "a", new: "b" }],
    );
    expect(objectLabel(unnamed, { kind: "host", id: A })).toBeUndefined();
  });

  it("builds the filter value that selects one object", () => {
    expect(objectFilter({ kind: "host", id: A.toUpperCase() })).toBe(`host:${A}`);
  });
});

describe("small facts about records", () => {
  it("builds the subject the principal filter takes", () => {
    expect(principalSubject({ kind: "user", id: A, session: B, strength: "passkey" })).toBe(`user:${A}`);
    expect(principalSubject({ kind: "token", id: A, owner: B })).toBe(`token:${A}`);
    expect(principalSubject({ kind: "system", component: "ipam" })).toBe("system:ipam");
    expect(principalSubject({ kind: "node", id: 3 })).toBe("node:3");
  });

  it("shortens a digest and recognizes the all-zero one", () => {
    expect(shortHash("0123456789abcdef0123456789abcdef")).toBe("0123456789ab");
    expect(isZeroHash("0".repeat(64))).toBe(true);
    expect(isZeroHash(`${"0".repeat(63)}1`)).toBe(false);
  });
});
