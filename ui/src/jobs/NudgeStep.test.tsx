import { render, screen, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it } from "vitest";
import { encodeMoveNudgeOutput, type MoveNudgeOutput, type NudgeChange } from "../api/moves";
import type { StepPreview, StepRecord, StepState } from "../api/types";
import { axeViolations } from "../app/testing/axe";
import { IconSprite } from "../components/Icon";
import { setLocale } from "../i18n";
import { NudgeStep } from "./NudgeStep";

const CONNECTOR = "0190d1c2-0000-7000-8000-0000000d0001";
const SWITCH = "00:00:5e:00:53:03";
const MAC = "00:00:5e:00:53:2b";

const BOUNCE: NudgeChange = { type: "bounce_port", data: { device: SWITCH, port: 5, down_secs: 5 } };
const KICK: NudgeChange = { type: "kick_client", data: { mac: MAC } };

beforeEach(async () => {
  await setLocale("en");
});

function minutesAgo(minutes: number): string {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

function stepOf(state: StepState, output?: MoveNudgeOutput | string): StepRecord {
  const step: StepRecord = { index: 2, kind: "ipam.move.nudge", state, attempts: 1 };
  if (output !== undefined) step.output = typeof output === "string" ? output : encodeMoveNudgeOutput(output);
  return step;
}

const PREVIEW: StepPreview = { summary: "ipam.move.step.nudge_bounce", args: { device: "sw1", port: "5", connector: "unifi-lab" }, changes: [] };

function show(step: StepRecord, preview: StepPreview | null = PREVIEW) {
  return render(() => (
    <>
      <IconSprite />
      <NudgeStep step={step} preview={preview ?? undefined} />
    </>
  ));
}

const text = (testid: string) => screen.getByTestId(testid).textContent;

describe("what the nudge step did", () => {
  it("says the device came back by itself, by its DHCP exchange or by its lease", () => {
    const view = show(stepOf({ state: "done" }, { change: BOUNCE, reappeared_at: minutesAgo(3), reappeared_by: "dhcp" }));
    expect(text("job-nudge-reappeared")).toMatch(/^The device came back by itself 3 minutes ago: its DHCP exchange on the new network was seen\. Its port was not bounced/);
    expect(screen.getByTestId("job-nudge").getAttribute("aria-label")).toBe("After the network change");
    expect(screen.queryByTestId("job-nudge-bounced")).toBeNull();
    view.unmount();

    show(stepOf({ state: "done" }, { change: BOUNCE, reappeared_at: minutesAgo(3), reappeared_by: "lease" }));
    expect(text("job-nudge-reappeared")).toMatch(/its lease on the new network was seen\./);
  });

  it("says when the port went down and when it was up again", () => {
    show(
      stepOf(
        { state: "done" },
        { change: BOUNCE, report: { connector: CONNECTOR, change: BOUNCE, at: minutesAgo(5), up_at: minutesAgo(4), outcome: "done" } },
      ),
    );
    expect(text("job-nudge-bounced")).toBe("Port 5 of sw1 went down 5 minutes ago and was up again 4 minutes ago.");
  });

  it("names the switch by its reference when the preview has no name, and keeps to the down time without an up time", () => {
    show(
      stepOf({ state: "done" }, { change: BOUNCE, report: { connector: CONNECTOR, change: BOUNCE, at: minutesAgo(5), outcome: "done" } }),
      null,
    );
    expect(text("job-nudge-bounced")).toBe(`Port 5 of ${SWITCH} went down 5 minutes ago.`);
  });

  it("says the client was disconnected", () => {
    show(stepOf({ state: "done" }, { change: KICK, report: { connector: CONNECTOR, change: KICK, at: minutesAgo(2), outcome: "done" } }));
    expect(text("job-nudge-kicked")).toBe("The device was disconnected from its access point 2 minutes ago; it connects again by itself.");
  });

  it("says why nothing was done: a failed kick, a guardrail, a port that stayed down", () => {
    const failed = show(
      stepOf(
        { state: "done" },
        { change: KICK, report: { connector: CONNECTOR, change: KICK, at: minutesAgo(2), outcome: "failed", code: "connect.timeout", detail: "no answer" } },
      ),
    );
    expect(text("job-nudge-failed")).toBe("Not done: The plugin did not answer in time.");
    failed.unmount();

    const refused = show(
      stepOf({ state: "done" }, { change: BOUNCE, problem: { code: "connect.guardrail.shared_port", detail: "2 devices on port 5" } }),
    );
    expect(text("job-nudge-failed")).toBe("Not done: Other devices use this switch port; Tenko does not bounce it.");
    refused.unmount();

    const stuck = show(
      stepOf(
        { state: "failed", data: { error: { code: "connect.port_stuck", status: 502, title: "t", detail: "d" } } },
        {
          change: BOUNCE,
          report: { connector: CONNECTOR, change: BOUNCE, at: minutesAgo(1), outcome: "stuck", code: "connect.port_stuck", detail: "still down" },
        },
      ),
    );
    expect(text("job-nudge-failed")).toBe("Not done: Port 5 of sw1 on 0190d1c2-0000-7000-8000-0000000d0001 did not come up again after the bounce (still down). Tenko keeps trying; you can also switch it on at the controller.");
    stuck.unmount();

    // A code this UI does not know keeps the server's detail.
    show(stepOf({ state: "done" }, { change: KICK, report: { connector: CONNECTOR, change: KICK, outcome: "failed", code: "connect.future", detail: "the detail" } }));
    expect(text("job-nudge-failed")).toBe("Not done: the detail");
  });

  it("says the step ran again after an interruption without a second nudge", () => {
    show(stepOf({ state: "done" }, { change: BOUNCE, interrupted: true }));
    expect(text("job-nudge-interrupted")).toBe("The step ran again after an interruption; it does not bounce or disconnect a second time.");
    expect(within(screen.getByTestId("job-nudge")).queryAllByTestId(/job-nudge-(bounced|kicked|failed)/)).toHaveLength(0);
  });

  it("shows nothing before the step has run, without output or with output it cannot read", () => {
    const output: MoveNudgeOutput = { change: BOUNCE, report: { connector: CONNECTOR, change: BOUNCE, at: minutesAgo(1), outcome: "done" } };
    for (const step of [stepOf({ state: "pending" }, output), stepOf({ state: "running" }, output), stepOf({ state: "done" }), stepOf({ state: "done" }, "zz"), stepOf({ state: "done" }, "7b7d")]) {
      const view = show(step);
      expect(screen.queryByTestId("job-nudge")).toBeNull();
      view.unmount();
    }
  });

  it("passes axe, in Swedish too", async () => {
    show(stepOf({ state: "done" }, { change: BOUNCE, report: { connector: CONNECTOR, change: BOUNCE, at: minutesAgo(5), up_at: minutesAgo(4), outcome: "done" } }));
    expect(await axeViolations(screen.getByTestId("job-nudge"))).toEqual([]);
    await setLocale("sv");
    expect(screen.getByTestId("job-nudge").getAttribute("aria-label")).toBe("Efter nätbytet");
    expect(text("job-nudge-bounced")).toMatch(/^Port 5 på sw1 gick ned/);
  });
});
