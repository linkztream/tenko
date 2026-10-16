#!/usr/bin/env python3
"""heapsym.py DUMP BINARY [TOP]: symbolise a heapshim dump and group its bytes.

Prints (1) the top stacks by live bytes with their first frames inside the binary,
(2) live bytes grouped by the first 'interesting' frame (skipping allocator and std
plumbing), (3) live bytes grouped by crate of that frame, (4) bytes allocated since the
start (each realloc counted at its new size) grouped by that frame."""
import re, subprocess, sys, collections

dump, binary = sys.argv[1], sys.argv[2]
top = int(sys.argv[3]) if len(sys.argv) > 3 else 40
maps, stacks, cums, mode = [], [], [], None
for line in open(dump, errors="replace"):
    line = line.rstrip("\n")
    if line in ("MAPS", "STACKS"):
        mode = line; continue
    if line.startswith("TOTALS"):
        print(line); continue
    if mode == "MAPS":
        f = line.split()
        if len(f) >= 6:
            a, b = (int(x, 16) for x in f[0].split("-"))
            maps.append((a, b, int(f[2], 16), f[5]))
    elif mode == "STACKS" and line.startswith("S "):
        f = line.split()
        stacks.append((int(f[1]), int(f[2]), [int(x, 16) for x in f[5:]]))
        cums.append((int(f[3]), int(f[4])))
    elif line.startswith("TOTALS"):
        print(line)

binname = binary.rsplit("/", 1)[-1]
binmaps = [m for m in maps if m[3].endswith("/" + binname)]
loads = []
for l in subprocess.run(["readelf", "-lW", binary], capture_output=True, text=True).stdout.splitlines():
    f = l.split()
    if f and f[0] == "LOAD":
        loads.append((int(f[1], 16), int(f[2], 16), int(f[4], 16)))  # offset, vaddr, filesz
def rel(pc):
    for a, b, off, name in binmaps:
        if a <= pc < b:
            fo = pc - a + off
            for o, v, sz in loads:
                if o <= fo < o + sz:
                    return fo - o + v
            return fo
    return None

pcs = sorted({p for _, _, s in stacks for p in s if rel(p) is not None})
names = {}
CH = 20000
for i in range(0, len(pcs), CH):
    chunk = pcs[i:i + CH]
    # File offset equals virtual address for the usual PIE layout of rustc output;
    # addr2line wants the virtual address, so map through the program headers.
    out = subprocess.run(["addr2line", "-f", "-C", "-e", binary] + [hex(rel(p) - 1) for p in chunk],
                         capture_output=True, text=True).stdout.splitlines()
    for j, p in enumerate(chunk):
        names[p] = re.sub(r"::h[0-9a-f]{16}$", "", out[2 * j])

SKIP = re.compile(r"^(\?\?|__rust|alloc::|<alloc::|core::|<core::|std::|<std::|hashbrown::|<hashbrown::|"
                  r"__libc|_start|main$|malloc|calloc|realloc|<?bytes::|<?smallvec::|indexmap::|<indexmap::|"
                  r"<?serde|<?toml|<?regex|<?tokio::runtime|<?tokio::task|<?tokio::loom|<?futures)")
total = sum(l for l, _, _ in stacks if l > 0)
print(f"live bytes tracked: {total/1048576:.2f} MiB in {sum(c for _, c, _ in stacks)} blocks, {len(stacks)} stacks")

def frames(s):
    return [names[p] for p in s if p in names]
def key(s):
    fr = frames(s)
    for f in fr:
        if not SKIP.match(f):
            return f
    return fr[0] if fr else "(outside the binary)"
def crate(f):
    m = re.match(r"^<?(?:&?(?:mut )?)?([a-zA-Z0-9_]+)", f)
    return m.group(1) if m else f

by = collections.Counter(); byc = collections.Counter(); cnt = collections.Counter()
for l, c, s in stacks:
    if l <= 0: continue
    k = key(s); by[k] += l; cnt[k] += c; byc[crate(k)] += l
print("\n== by crate of first interesting frame (MiB)")
for k, v in byc.most_common(25):
    print(f"{v/1048576:8.2f}  {k}")
print("\n== by first interesting frame (MiB, blocks)")
for k, v in by.most_common(top):
    print(f"{v/1048576:8.2f} {cnt[k]:7d}  {k[:150]}")
bycum = collections.Counter(); bycalls = collections.Counter()
for (l, c, s), (cb, cc) in zip(stacks, cums):
    k = key(s); bycum[k] += cb; bycalls[k] += cc
print("\n== cumulative bytes allocated since start, by first interesting frame (MiB, calls)")
for k, v in bycum.most_common(25):
    print(f"{v/1048576:9.2f} {bycalls[k]:9d}  {k[:150]}")
print("\n== top stacks")
for l, c, s in sorted(stacks, key=lambda x: -x[0])[:15]:
    print(f"--- {l/1048576:.2f} MiB in {c} blocks")
    for f in frames(s)[:18]:
        print("     " + f[:160])
