# PGO for applications that embed the engine

If your WAF depends on `zentinel-modsec`, enable profile-guided optimization (PGO) when building the WAF executable. Cargo applies the compiler flags to that executable and its Rust dependencies.

Run the commands below in the application's Cargo workspace with a committed `Cargo.lock`. Set `app` to your Cargo binary name. Use an `llvm-profdata` whose LLVM version matches `rustc -vV`, and keep the toolchain, target, features and other release flags the same across both builds.

**1. Build and run the instrumented application.** Append your usual agent arguments after `--`. While it runs, replay representative traffic through it with your normal rules and audit settings. Stop the agent gracefully so LLVM writes the counters.

```sh
app=my-waf-agent
host=$(rustc -vV | sed -n 's/^host: //p')
profiles=$(mktemp -d /tmp/waf-pgo.XXXXXX)
mkdir "$profiles/raw"

LLVM_PROFILE_FILE="$profiles/raw/%m-%p.profraw" \
RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Cprofile-generate=$profiles/raw" \
    cargo run --locked --release --target "$host" --bin "$app" --
```

**2. Merge the counters and build the executable to deploy.** In the same shell, run

```sh
llvm-profdata merge -o "$profiles/waf.profdata" "$profiles"/raw/*.profraw
RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Cprofile-use=$profiles/waf.profdata" \
    cargo build --locked --release --target "$host" --bin "$app"
```

The optimized agent is in `${CARGO_TARGET_DIR:-target}/$host/release/$app` with Cargo's default target directory settings. Compare it with your ordinary release on a separate traffic replay, checking latency, blocking decisions and the audit fields your connector consumes.
