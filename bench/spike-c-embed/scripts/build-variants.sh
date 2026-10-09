#!/usr/bin/env bash
# Builds every server variant (release profile) and copies the binaries to
# results/raw/bin/<variant>.exe, then prints each variant's startup line.
#
# Variants: embedding backend (include_dir, rust-embed, codegen) x UI payload
# (empty, real ui/dist, synthetic large bundle) x compression strategy.
set -euo pipefail
cd "$(dirname "$0")/.."

RAW=results/raw
BIN=$RAW/bin
mkdir -p "$BIN" "$RAW/empty-dist"

# Synthetic large bundle: the real UI build plus ~1.8 MiB of real (unminified) JavaScript
# taken from Vite's own Node build, as a stand-in for a grown application bundle.
SYN=$RAW/synthetic-dist
rm -rf "$SYN"
cp -r ../../ui/dist "$SYN"
CHUNKS=../../ui/node_modules/vite/dist/node/chunks
cat "$CHUNKS/node.js" "$CHUNKS/dist.js" "$CHUNKS/build.js" > "$SYN/assets/vendor-synthetic-0a1b2c3d.js"

# Separate target dir, so that other builds of this package cannot race with the copies.
VARIANT_TARGET=target/variants

EXE=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; esac

build() {
    local name=$1 features=$2 dist=${3:-}
    if [ -n "$dist" ]; then
        # Relative paths are resolved against the package directory by build.rs.
        export SPIKE_UI_DIST="$dist"
    else
        unset SPIKE_UI_DIST
    fi
    echo "=== $name: features=[$features] dist=${dist:-../../ui/dist}"
    cargo build --release --quiet --target-dir "$VARIANT_TARGET" --bin spike-c-embed --no-default-features --features "$features"
    cp "$VARIANT_TARGET/release/spike-c-embed$EXE" "$BIN/$name$EXE"
}

build incdir-empty     backend-include-dir,precompressed  "$RAW/empty-dist"
build incdir-raw       backend-include-dir
build incdir-pre       backend-include-dir,precompressed
build incdir-runtime   backend-include-dir,runtime-compression
build incdir-raw-large backend-include-dir                "$SYN"
build incdir-pre-large backend-include-dir,precompressed  "$SYN"

build rustembed-empty         backend-rust-embed,precompressed "$RAW/empty-dist"
build rustembed-raw           backend-rust-embed
build rustembed-pre           backend-rust-embed,precompressed
build rustembed-deflate       rust-embed-compression
build rustembed-raw-large     backend-rust-embed               "$SYN"
build rustembed-pre-large     backend-rust-embed,precompressed "$SYN"
build rustembed-deflate-large rust-embed-compression           "$SYN"

build codegen-empty     backend-codegen,precompressed "$RAW/empty-dist"
build codegen-raw       backend-codegen
build codegen-pre       backend-codegen,precompressed
build codegen-raw-large backend-codegen               "$SYN"
build codegen-pre-large backend-codegen,precompressed "$SYN"

unset SPIKE_UI_DIST
cargo build --release --quiet --bin measure

echo
echo "=== startup lines"
for f in "$BIN"/*"$EXE"; do
    printf '%s: ' "$(basename "$f" "$EXE")"
    timeout 3 "$f" --listen 127.0.0.1:0 | head -n 1 || true
done
