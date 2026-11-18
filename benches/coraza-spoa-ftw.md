# Tagged Coraza and pure Rust CRS detection comparison

On 19 November 2026 the two backends produced identical pass and fail lists for the 4,672 executable stages in the OWASP CRS 4.25.0 go-ftw corpus. Both passed 4,649 stages and failed 23. One additional file failed in the test client before either engine received the request.

| Input | Version |
| --- | --- |
| Rust engine | `b206f2fb39d854628e755f95a0afdfb2d7ee1576`, frozen with `git archive` |
| Rust compiler options | `CompileOptions::CORAZA_SPOA`, default Cargo features disabled, Rust libinjection 0.1.3 |
| Go engine | Coraza v3.8.1 with `coraza.rule.multiphase_evaluation,coraza.rule.no_regex_multiline` |
| Rules and tests | coraza-coreruleset v4.25.0, go-ftw v2.6.2, albedo v0.3.0 |
| Toolchains | rustc 1.96.1 and Go 1.27.4, Linux amd64 |

The same local HTTP harness drove request, response and logging phases using the recommended configuration, example CRS setup and all CRS rules. The CRS test configuration sets DetectionOnly and paranoia level 4. Each verdict is a go-ftw stage expectation. Blocking behavior, latency, and SPOA callback result fields require their own comparisons. All 170 registry packages in the Rust worker lockfile matched versions and checksums in the connector lockfile.

The client rejected stage `921140-1` in both runs with `header "SomeHeader" contains a raw CR or LF character, which would corrupt the request`. The loopback destination ports differed. Both runner processes exited zero. The sorted success and failure lists were compared byte for byte because the exit status alone does not reflect failed stages.

| Output | SHA-256, identical on Go and Rust |
| --- | --- |
| 4,649 passing stage IDs | `723fe2dd3fb417696519570fb816d878383eb81157ba69e68e8aff9eb053dc7f` |
| 23 failing stage IDs | `29b8c4cf25ef0903160a49835a91d53366e85c936b3d6d3100714f9ca5d10d36` |

## Replay inputs

The qualification workspace stores the adapter sources and complete run logs in `zentinel-eval/results/tagged-ftw-WgKj4q`. The adapter sources are a prerequisite for these commands. Start in that directory with the frozen engine at `b206f2f/engine`.

```sh
run="$PWD/b206f2f"
rules="$(go env GOMODCACHE)/github.com/corazawaf/coraza-coreruleset/v4@v4.25.0/rules"
config="$PWD/../parity-goal/ftw-zentinel-v2.conf"
(cd ftw && go build -mod=readonly -tags=coraza.rule.multiphase_evaluation,coraza.rule.no_regex_multiline -o ../ftw-tagged .)
CARGO_TARGET_DIR="$run/target" cargo build --locked --manifest-path "$run/worker/Cargo.toml"
./ftw-tagged -engine coraza -recommended "$rules/@coraza.conf-recommended" -log "$run/go.log"
./ftw-tagged -engine zentinel -worker "$run/target/debug/zworker-v2" -zconf "$config" -recommended "$rules/@coraza.conf-recommended" -log "$run/rust.log"
cmp "$run/go.log.success" "$run/rust.log.success"
cmp "$run/go.log.failed" "$run/rust.log.failed"
```

| Adapter input | SHA-256 |
| --- | --- |
| `ftw/main.go` | `388b338c24bbbed78d0e8c01f1db94249d7d37728d0c9da604fd10a7c35400b6` |
| `ftw/go.mod` | `5448714ffea30d78401b05575e7249d8bcfeec55465c830205a43a5642fc0633` |
| `ftw/go.sum` | `7c2d326caa85dc44bc9a60a7a0105b0926140e722c69f9ae3e969255746ef561` |
| `b206f2f/worker/src/main.rs` | `6e28040708c6484cfabc0f9508081ef5416934580f151d15e90416dd266a8751` |
| `b206f2f/worker/Cargo.toml` | `8fda42c1966cbb3705420ccc80a68367ad182689a81ff0123d28a13e000539a0` |
| `b206f2f/worker/Cargo.lock` | `27082f5d28b44650ae72ef454f663a3dd3647e80776c3e17e2ec26ab8b3f32cd` |
| Rust CRS configuration | `9ddeb44d69c61e2d29771ab1aba96a58ff9881d84edee74ba21ae428206e176d` |
