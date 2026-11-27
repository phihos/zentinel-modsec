#!/usr/bin/env bash
# Build the engine CLI and timing example using the pinned CRS training workload.
set -euo pipefail

: "${CRS_BENCH_DIR:?set CRS_BENCH_DIR to your CRS 4.25.0 checkout}"
export CRS_BENCH_DIR
CRS_BENCH_DIR=$(cd "$CRS_BENCH_DIR" && pwd)
cd "$(dirname "$0")/.."
host=$(rustc -vV | sed -n 's/^host: //p')
profdata=${LLVM_PROFDATA:-llvm-profdata}
"$profdata" --version >/dev/null

export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-target/profiled}
mkdir -p "$CARGO_TARGET_DIR/profiles"
CARGO_TARGET_DIR=$(cd "$CARGO_TARGET_DIR" && pwd)
profile_dir=$(mktemp -d "$CARGO_TARGET_DIR/profiles/crs.XXXXXX")
raw="$profile_dir/raw"
mkdir "$raw"
trap 'rm -rf -- "$raw"' EXIT

# Cargo accepts unit-separated flags so a profile path can contain spaces.
if [[ -v CARGO_ENCODED_RUSTFLAGS ]]; then
    inherited=$CARGO_ENCODED_RUSTFLAGS
else
    read -r -a flags <<< "${RUSTFLAGS:-}"
    inherited=$(IFS=$'\x1f'; printf '%s' "${flags[*]}")
fi
prefix=${inherited:+$inherited$'\x1f'}
args=(--release --target "$host" "$@")
LLVM_PROFILE_FILE="$raw/%m-%p.profraw" CARGO_ENCODED_RUSTFLAGS="${prefix}-Cprofile-generate=$raw" \
    cargo run "${args[@]}" --example crs_latency -- train
profile="$profile_dir/crs.profdata"
"$profdata" merge -o "$profile" "$raw"/*.profraw
CARGO_ENCODED_RUSTFLAGS="${prefix}-Cprofile-use=$profile" \
    cargo build --locked "${args[@]}" --bin zentinel-modsec --example crs_latency
printf 'Executable: %s\nProfile: %s\n' "$CARGO_TARGET_DIR/$host/release/zentinel-modsec" "$profile"
