import { describe, expect, it, vi } from "vitest";
import type * as Meta from "virtual:tenko-i18n/meta";

// One message pack with one key, in English and Swedish. Tests otherwise run without packs.
vi.mock("virtual:tenko-i18n/meta", async (importOriginal) => {
  const real = await importOriginal<typeof Meta>();
  return {
    ...real,
    packs: {
      sample: {
        en: async () => ({ default: { "sample.greeting": "Hello from the pack" } }),
        sv: async () => ({ default: { "sample.greeting": "Second language text from the pack" } }),
      },
    },
  };
});

// The test setup has loaded the i18n module already; load a fresh copy (and the solid-js it
// uses) that sees the pack above.
vi.resetModules();
const { createEffect, createRoot } = await import("solid-js");
const i18n = await import("./index");
const key = "sample.greeting" as Parameters<typeof i18n.t>[0];

describe("message packs", () => {
  it("adds the keys of a pack and reads a text again when its pack arrives", async () => {
    expect(i18n.hasMessage("sample.greeting")).toBe(false);
    const seen: string[] = [];
    const dispose = createRoot((done) => {
      createEffect(() => seen.push(i18n.t(key)));
      return done;
    });
    expect(seen).toEqual(["sample.greeting"]);
    await i18n.loadPacks(["sample", "unknown"]);
    expect(i18n.hasMessage("sample.greeting")).toBe(true);
    expect(seen).toEqual(["sample.greeting", "Hello from the pack"]);
    dispose();
  });

  it("loads a pack in a language chosen later", async () => {
    await i18n.loadPacks(["sample"]);
    await i18n.setLocale("sv");
    expect(i18n.t(key)).toBe("Second language text from the pack");
    await i18n.setLocale("en");
    expect(i18n.t(key)).toBe("Hello from the pack");
  });

  it("waits for the packs of a route before its module", async () => {
    const view = { default: "view" };
    const load = i18n.withPacks(["sample"], async () => view);
    await expect(load()).resolves.toBe(view);
  });
});
