import { describe, expect, it } from "vitest";
import { lockPolicyOf, lockoutPatch, parseWaits, toPinDays, type LockDraft } from "./toggleEdit";

const draft: LockDraft = { attempts: "3", waits: "10, 30, 180, 300, 600", lock: "30", lockUnit: "minutes", account: "60" };

describe("the lock policy of the form", () => {
  it("turns the fields into the numbers of the API", () => {
    expect(lockPolicyOf(draft, true).policy).toEqual({
      attempts: 3,
      waits_secs: [10, 30, 180, 300, 600],
      lock_secs: 1800,
      account_max_delay_secs: 60,
      passkey_holds_lock: true,
    });
    expect(lockPolicyOf({ ...draft, lock: "1", lockUnit: "days" }, false).policy?.lock_secs).toBe(86_400);
  });

  it("names the fields that are out of bounds", () => {
    const errors = (change: Partial<LockDraft>) => Object.keys(lockPolicyOf({ ...draft, ...change }, false).errors);
    expect(errors({})).toEqual([]);
    expect(errors({ attempts: "0" })).toEqual(["attempts"]);
    expect(errors({ attempts: "21" })).toEqual(["attempts"]);
    expect(errors({ attempts: "1" })).toEqual([]);
    expect(errors({ attempts: "20" })).toEqual([]);
    expect(errors({ waits: "" })).toEqual(["waits"]);
    expect(errors({ waits: "0" })).toEqual(["waits"]);
    expect(errors({ waits: "86401" })).toEqual(["waits"]);
    expect(errors({ waits: "86400" })).toEqual([]);
    expect(errors({ lock: "59", lockUnit: "minutes" })).toEqual([]);
    expect(errors({ lock: "2", lockUnit: "days" })).toEqual(["lock"]);
    expect(errors({ account: "601" })).toEqual(["account"]);
    expect(errors({ account: "0" })).toEqual([]);
    expect(errors({ attempts: "x", waits: "a", lock: "", account: "-1" })).toEqual(["attempts", "waits", "lock", "account"]);
  });

  it("takes 1 to 10 waits", () => {
    expect(parseWaits("1")).toEqual([1]);
    expect(parseWaits("1,2,3,4,5,6,7,8,9,10")).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(parseWaits("1,2,3,4,5,6,7,8,9,10,11")).toBeUndefined();
    expect(parseWaits("10,,30")).toBeUndefined();
  });

  it("sends the mode in lockout and the numbers in lockout_policy", () => {
    const policy = lockPolicyOf(draft, false).policy!;
    expect(lockoutPatch({ mode: "lock_until_unlock", ...policy })).toEqual({ lockout: "lock_until_unlock", lockout_policy: policy });
  });

  it("takes the period of unconfirmed PINs from 1 to 365 days", () => {
    expect(toPinDays("30")).toBe(30);
    expect(toPinDays(" 365 ")).toBe(365);
    expect(toPinDays("1")).toBe(1);
    for (const bad of ["0", "366", "", "1.5", "x", "-3"]) expect(toPinDays(bad), bad).toBeUndefined();
  });
});
