import { screen, waitFor } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { ipamState } from "../api/mock/ipam/api";
import type { Host } from "../api/types";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { applied, confirmPlan, recordWrites, submitForm, typeInto } from "../ipam/testkit";
import { HostForm } from "./HostForm";

/** A seeded host by name, as the mock holds it now. */
function host(name: string): Host {
  const found = [...ipamState().data.host.values()].find((h) => h.name === name && !h.meta.deleted);
  if (!found) throw new Error(`no host ${name}`);
  return structuredClone(found);
}

async function edit(name: string) {
  const writes = recordWrites();
  const done = vi.fn();
  renderRoute(() => <HostForm host={host(name)} onDone={done} onClose={() => {}} />);
  await screen.findByTestId("dialog-host-form");
  return { writes, done };
}

async function save(done: ReturnType<typeof vi.fn>) {
  submitForm();
  await confirmPlan();
  await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
}

beforeEach(async () => {
  await signInAlex();
});

describe("host form custom values", () => {
  it("removes a cleared value by sending it as null", async () => {
    // The seeded nas carries asset_tag A-0042.
    expect(host("nas").meta.custom).toEqual({ asset_tag: { type: "text", value: "A-0042" } });
    const { writes, done } = await edit("nas");
    await waitFor(() => expect(screen.getByTestId("field-custom-asset_tag")).toBeTruthy());
    typeInto("field-custom-asset_tag", "");
    await save(done);
    expect(applied(writes())[0]?.body).toEqual({ custom: { asset_tag: null } });
    expect(host("nas").meta.custom ?? {}).toEqual({});
  });

  it("sends only the value that changed and keeps the others", async () => {
    await api.post("/api/v1/custom-fields", { body: { key: "owner", kind: { type: "text" }, applies_to: ["host"], required: false } });
    const { writes, done } = await edit("nas");
    await waitFor(() => expect(screen.getByTestId("field-custom-owner")).toBeTruthy());
    typeInto("field-custom-owner", "alex");
    await save(done);
    expect(applied(writes())[0]?.body).toEqual({ custom: { owner: { type: "text", value: "alex" } } });
    expect(host("nas").meta.custom).toEqual({
      asset_tag: { type: "text", value: "A-0042" },
      owner: { type: "text", value: "alex" },
    });
  });

  it("leaves the custom values out of a change that does not touch them", async () => {
    const { writes, done } = await edit("nas");
    typeInto("field-description", "Storage server in the hall");
    await save(done);
    expect(applied(writes())[0]?.body).toEqual({ description: "Storage server in the hall" });
    expect(host("nas").meta.custom).toEqual({ asset_tag: { type: "text", value: "A-0042" } });
  });
});
