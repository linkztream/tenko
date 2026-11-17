// Every accepted advisory in deny.toml carries a review date, and none has passed.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

test("accepted advisories have a review date that has not passed", () => {
  const text = readFileSync(new URL("../deny.toml", import.meta.url), "utf8");
  const entries = [...text.matchAll(/\{\s*id\s*=\s*"([^"]+)"\s*,\s*reason\s*=\s*"([^"]*)"\s*\}/g)];
  const today = new Date().toISOString().slice(0, 10);
  for (const [, id, reason] of entries) {
    const date = /review by (\d{4}-\d{2}-\d{2})$/.exec(reason)?.[1];
    assert.ok(date, `${id}: the reason ends with "review by YYYY-MM-DD"`);
    assert.ok(date >= today, `${id}: its review date ${date} has passed; decide again`);
  }
});
