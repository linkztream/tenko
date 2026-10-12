// The partition state: the staleness header, the `cluster.quorum` event, the body of a queued
// write, and how the three sources of the quorum combine.
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import { server } from "../api/mock/node";
import { queueRequestOf } from "./api";
import { partition, quorumOfEvent, refusesWrites } from "./partition";
import { parseStaleness, sinceText } from "./PartitionStatus";

afterEach(() => partition.reset());

describe("parseStaleness", () => {
  it("reads since and revision in any order and spacing", () => {
    expect(parseStaleness("since=2026-10-11T08:00:00Z; revision=420")).toEqual({ since: "2026-10-11T08:00:00Z", revision: 420 });
    expect(parseStaleness("revision=7;since=2026-10-11T08:00:00Z")).toEqual({ since: "2026-10-11T08:00:00Z", revision: 7 });
    expect(parseStaleness("since=2026-10-11T08:00:00Z")).toEqual({ since: "2026-10-11T08:00:00Z", revision: null });
  });

  it("is null without a header or with a malformed one", () => {
    expect(parseStaleness(null)).toBeNull();
    expect(parseStaleness("")).toBeNull();
    expect(parseStaleness("revision=4")).toBeNull();
    expect(parseStaleness("since=yesterday; revision=4")).toBeNull();
  });
});

describe("quorumOfEvent", () => {
  it("reads the params of a cluster.quorum event", () => {
    const data = { kind: "cluster.quorum", params: { state: "isolated", since: "2026-10-11T08:00:00Z", applied: "512" } };
    expect(quorumOfEvent({ data })).toEqual({ state: "isolated", since: "2026-10-11T08:00:00Z", applied: 512 });
  });

  it("ignores other events and an event without a state", () => {
    expect(quorumOfEvent({ data: { kind: "cluster.node" } })).toBeNull();
    expect(quorumOfEvent({ data: { kind: "cluster.quorum", params: {} } })).toBeNull();
  });
});

describe("queueRequestOf", () => {
  it("keeps the path, the query without dry_run, the body and the revision", () => {
    const body = { hostname: "web.example.test" };
    const request = queueRequestOf({ method: "patch", url: "/api/v1/addresses/a1?dry_run=true&acknowledge=x", body, ifMatch: 41 });
    expect(request).toEqual({ method: "patch", path: "/api/v1/addresses/a1", query: { acknowledge: "x" }, body, if_match: "41" });
  });

  it("sends nulls for what the write did not have", () => {
    expect(queueRequestOf({ method: "delete", url: "/api/v1/hosts/h1", body: undefined, ifMatch: undefined })).toEqual({
      method: "delete",
      path: "/api/v1/hosts/h1",
      query: null,
      body: null,
      if_match: null,
    });
  });
});

describe("the partition store", () => {
  it("refuses writes only while isolated or electing", () => {
    expect(refusesWrites({ state: "isolated" })).toBe(true);
    expect(refusesWrites({ state: "electing" })).toBe(true);
    expect(refusesWrites({ state: "healthy" })).toBe(false);
    expect(refusesWrites(null)).toBe(false);
  });

  it("records a write refused with cluster.no_quorum and marks the controller isolated", async () => {
    const uninstall = partition.install();
    server.use(
      http.post("/api/v1/hosts", () =>
        HttpResponse.json(
          { status: 503, code: "cluster.no_quorum", title: "", detail: "", params: { since: "2026-10-11T08:00:00Z", queueable: "true" } },
          { status: 503, headers: { "Retry-After": "5", "Tenko-Staleness": "since=2026-10-11T08:00:00Z; revision=9" } },
        ),
      ),
    );
    await expect(api.post("/api/v1/hosts", { body: { fqdn: "web.example.test" } as never })).rejects.toThrow();
    expect(partition.refused()?.write.url).toBe("/api/v1/hosts");
    expect(partition.quorum()).toEqual({ state: "isolated", since: "2026-10-11T08:00:00Z" });
    expect(partition.staleness()).toBe("since=2026-10-11T08:00:00Z; revision=9");
    partition.setRefused(null);
    expect(partition.refused()).toBeNull();
    uninstall();
  });
});

describe("sinceText", () => {
  it("rounds down to the largest whole unit", () => {
    const at = Date.parse("2026-10-11T08:00:00Z");
    expect(sinceText("2026-10-11T08:00:00Z", at + 42_000)).toBe("42 sec");
    expect(sinceText("2026-10-11T08:00:00Z", at + 4 * 60_000 + 30_000)).toBe("4 min");
    expect(sinceText("2026-10-11T08:00:00Z", at + 3 * 3_600_000 + 60_000)).toBe("3 hr");
    expect(sinceText(null, at)).toBeNull();
  });
});
