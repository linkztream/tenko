#!/bin/bash
# The figures of RESULT.md: a clean release build for x86_64-unknown-linux-musl per feature
# set (wall clock and stripped size), the Windows target checks, and cargo geiger.
#
#   bash scripts/measure.sh /tmp/measure
#
# Needs the musl target (`rustup target add x86_64-unknown-linux-musl`), musl-tools, GNU time,
# and for the Windows checks the two targets (`x86_64-pc-windows-gnu`, `x86_64-pc-windows-msvc`).
# `cargo check` for the msvc target fails on aws-lc-sys without MSVC's compiler; the check of
# sspi alone is what the plan's criterion asks, and it runs on both targets.
set -u
OUT=${1:-/tmp/measure}
HERE=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUT"
cd "$HERE" || exit 1
rustc -Vv > "$OUT/rustc.txt"; cargo -V >> "$OUT/rustc.txt"
for v in base own sspi both; do
  case $v in
    base) F="--no-default-features";;
    own)  F="--no-default-features --features own";;
    sspi) F="--no-default-features --features sspi";;
    both) F="";;
  esac
  T=$OUT/target-$v; rm -rf "$T"
  /usr/bin/time -f "$v: wall %e s, user %U s, sys %S s, maxrss %M KiB" -o "$OUT/time-$v.txt" \
    cargo build --release --locked --target x86_64-unknown-linux-musl $F --target-dir "$T" > "$OUT/build-$v.log" 2>&1
  echo "$v build exit $?" >> "$OUT/build-status.txt"
  cp "$T/x86_64-unknown-linux-musl/release/spike-krb" "$OUT/spike-krb-$v"
  strip -o "$OUT/spike-krb-$v.stripped" "$OUT/spike-krb-$v"
  file "$OUT/spike-krb-$v.stripped" >> "$OUT/file.txt"
  rm -rf "$T"
done
ls -l "$OUT"/spike-krb-* > "$OUT/sizes.txt"
cat "$OUT"/time-*.txt
cat "$OUT/sizes.txt"
# Windows targets: the spike (all features) and sspi alone.
for t in x86_64-pc-windows-gnu x86_64-pc-windows-msvc; do
  cargo check --locked --target $t --target-dir "$OUT/target-win" > "$OUT/check-spike-$t.log" 2>&1
  echo "spike $t: exit $?" >> "$OUT/check-win.txt"
done
mkdir -p "$OUT/sspi-only/src"
cat > "$OUT/sspi-only/Cargo.toml" <<EOT
[package]
name = "sspi-windows-check"
version = "0.1.0"
edition = "2024"
[dependencies]
sspi = { version = "=0.23.1", default-features = false }
EOT
echo 'fn main() { let _ = sspi::kerberos::ServerProperties::new(&["DNS", "h"], None, std::time::Duration::from_secs(300), None); }' > "$OUT/sspi-only/src/main.rs"
for t in x86_64-pc-windows-gnu x86_64-pc-windows-msvc; do
  (cd "$OUT/sspi-only" && cargo check --target $t --target-dir "$OUT/target-win-sspi" > "$OUT/check-sspi-$t.log" 2>&1)
  echo "sspi-only $t: exit $?" >> "$OUT/check-win.txt"
done
rm -rf "$OUT/target-win" "$OUT/target-win-sspi"
cat "$OUT/check-win.txt"
# unsafe: cargo geiger (it did not honor --features in this environment, see RESULT.md), and a
# count of `unsafe` lines per crate of each tree from the registry sources.
cargo geiger --output-format Ascii --target-dir "$OUT/target-geiger" > "$OUT/geiger.txt" 2>&1
rm -rf "$OUT/target-geiger"
REG=$(ls -d ~/.cargo/registry/src/*/ | head -1)
for v in base own sspi; do
  case $v in base) F="--no-default-features";; own) F="--no-default-features --features own";; sspi) F="--no-default-features --features sspi";; esac
  cargo tree -e normal --prefix none $F | sed 's/ (.*//' | sort -u > "$OUT/tree-$v.txt"
  while read -r name ver; do
    d="$REG$name-${ver#v}"
    [ -d "$d/src" ] || continue
    n=$(grep -rnE --include='*.rs' '\bunsafe\b' "$d/src" | grep -vE '^\S+:\s*//|unsafe_code|undocumented_unsafe|multiple_unsafe|missing_safety|unnecessary_safety' | wc -l)
    [ "$n" != 0 ] && echo "$name $ver: $n"
  done < "$OUT/tree-$v.txt" | sort -t: -k2 -n -r > "$OUT/unsafe-$v.txt"
  echo "$v: $(wc -l < "$OUT/tree-$v.txt") crates, $(wc -l < "$OUT/unsafe-$v.txt") with unsafe lines, $(awk -F': ' '{s+=$2} END{print s+0}' "$OUT/unsafe-$v.txt") lines"
done
