#!/usr/bin/env python3
"""The tables of run-perfdhcp.sh's results from its raw directory.

    perfdhcp-report.py <raw dir>/summary.tsv <raw dir> > report.md

run-perfdhcp.sh calls it at the end of a run; it can also be run alone on a finished raw
directory. The better of the runs of a rung is the one that lost less, then answered more;
for M28 the one with the lower p99 from REQUEST to ACK.
"""
import csv, glob, os, re, sys
rows = list(csv.DictReader(open(sys.argv[1]), delimiter="\t"))
out = sys.argv[2]
def best(group, phase):
    # The offered rate is the same: the better run lost less, then answered more; for the
    # latency of M28 it is the one with the lower p99 from REQUEST to ACK.
    def key(r):
        if phase == "m28":
            p99 = r["ra_p99_ms"]
            return (float(p99) if p99 not in ("", "-") else float("inf"), round(ratio(r), 3))
        return (round(ratio(r), 3), -float(r["achieved"] or 0))
    return sorted(group, key=key)[0]
def groups(phase):
    seen = {}
    for r in rows:
        if r["phase"] == phase:
            seen.setdefault((int(r["workers"]), int(r["rate"])), []).append(r)
    return [(k, best(v, phase)) for k, v in sorted(seen.items())]
def ratio(r):
    s = int(r["do_sent"] or 0) + int(r["ra_sent"] or 0)
    d = int(r["do_drops"] or 0) + int(r["ra_drops"] or 0)
    return 100.0 * d / s if s else 100.0
print("## M26: 4-way exchanges per second (perfdhcp, better of the runs)\n")
print("| Workers | Offered /s | Achieved /s | Drops DO | Drops RA | Drop % | Avg DO ms | Avg RA ms |")
print("|---|---|---|---|---|---|---|---|")
ceil = {}
for (w, rate), r in groups("m26"):
    print(f"| {w} | {rate:,} | {int(r['achieved']):,} | {r['do_drops']} | {r['ra_drops']} | {ratio(r):.2f} | {r['do_avg_ms']} | {r['ra_avg_ms']} |")
    if ratio(r) <= 0.1:
        ceil[w] = max(ceil.get(w, 0), int(r["achieved"]))
print()
for w, c in sorted(ceil.items()):
    print(f"- ceiling with {w} worker(s): {c:,} per second (the highest rung with at most 0.1 % drops)")
def own(name, line):
    print(f"\nOwn client, closed loop ({name}), the better run:\n")
    print("| Workers | Run | Result |")
    print("|---|---|---|")
    found = {}
    for f in sorted(glob.glob(os.path.join(out, f"{name}-w*-*.txt"))):
        m = re.match(rf"{name}-w(\d+)-(\d+)\.txt", os.path.basename(f))
        text = [l for l in open(f).read().splitlines() if l.startswith(line)]
        rate = re.search(r"([\d.]+) per second", text[-1]) if text else None
        if m and rate:
            w = int(m.group(1))
            if w not in found or float(rate.group(1)) > found[w][0]:
                found[w] = (float(rate.group(1)), m.group(2), text[-1])
    for w, (_, run, text) in sorted(found.items()):
        print(f"| {w} | {run} | {text} |")
own("m26c", "dora")
print("\n## M27: renewals per second (perfdhcp -r R -f R: new 4-way exchanges and renewals at the same rate)\n")
print("| Workers | Offered renewals /s | Renewals answered /s | Renewal drops | 4-way /s |")
print("|---|---|---|---|---|")
for (w, rate), r in groups("m27"):
    print(f"| {w} | {rate:,} | {r['renew_rate']} | {r['renew_drops']} | {r['achieved']} |")
own("m27c", "renew")
print("\n## M28: latency at fixed rates (perfdhcp -x t; DISCOVER to ACK from the own client)\n")
print("| Workers | Rate /s | DO p50 ms | DO p99 ms | RA p50 ms | RA p99 ms | Own client DISCOVER to ACK |")
print("|---|---|---|---|---|---|---|")
for (w, rate), r in groups("m28"):
    client = []
    for f in sorted(glob.glob(os.path.join(out, f"m28c-w{w}-r{rate}-*.txt"))):
        m = re.search(r"p50 (\d+) p90 \d+ p99 (\d+)", open(f).read())
        if m:
            client.append((int(m.group(2)), int(m.group(1))))
    own_text = "p50 %.2f ms, p99 %.2f ms" % (min(client)[1] / 1000, min(client)[0] / 1000) if client else "-"
    print(f"| {w} | {rate:,} | {r['do_p50_ms']} | {r['do_p99_ms']} | {r['ra_p50_ms']} | {r['ra_p99_ms']} | {own_text} |")

# The server's own view of the M28 runs: the bucket that holds the quantile of its
# histograms (the example prints them; tenko's come from the metrics scrape).
def quantile(buckets, q):
    total = buckets[-1][1] if buckets else 0
    if not total:
        return "-"
    for bound, count in buckets:
        if count >= q * total:
            return "<= %g ms" % (bound * 1000) if bound != float("inf") else "> 1 s"
    return "-"
def histogram(text, name, label=None):
    rows = []
    for line in text.splitlines():
        if not line.startswith(name + "_bucket{") or (label and label not in line):
            continue
        m = re.search(r'le="([^"]+)"\}\s+([\d.e+]+)', line)
        if m:
            rows.append((float("inf") if m.group(1) == "+Inf" else float(m.group(1)), float(m.group(2))))
    return sorted(rows)
print("\nThe server's view of the M28 runs (the bucket of the quantile):\n")
print("| Run | REQUEST to ACK p50 | REQUEST to ACK p99 | Commit p50 | Commit p99 |")
print("|---|---|---|---|---|")
for f in sorted(glob.glob(os.path.join(out, "server-m28-*.log"))):
    name = os.path.basename(f)[len("server-"):-len(".log")]
    metrics = f + ".metrics"
    if os.path.exists(metrics):
        text = open(metrics).read()
        ack = histogram(text, "tenko_dhcp_exchange_duration_seconds", 'step="ack"')
        commit = histogram(text, "tenko_dhcp_commit_duration_seconds")
        cells = [quantile(ack, 0.5), quantile(ack, 0.99), quantile(commit, 0.5), quantile(commit, 0.99)]
    else:
        text = open(f).read()
        a = re.search(r"server ack: count \d+, p50 (\S+ \S+) us, p99 (\S+ \S+) us", text)
        c = re.search(r"server commit: count \d+, p50 (\S+ \S+) us, p99 (\S+ \S+) us", text)
        cells = [a.group(1) + " µs" if a else "-", a.group(2) + " µs" if a else "-",
                 c.group(1) + " µs" if c else "-", c.group(2) + " µs" if c else "-"]
    print(f"| {name} | " + " | ".join(cells) + " |")
