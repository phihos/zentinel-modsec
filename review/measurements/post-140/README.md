# November 26 request timings

The standalone patches use upstream 0.13.3 at `a3a5f2c`. The integration baseline combines the source changes from #137–140. The seven-PR build adds #141–143 to that baseline. The eight-PR build also includes #144. The final comparison uses #142 at `d968123`. The fork checkout is `phihos/zentinel-modsec@3d1fd5c`.

## Clean CRS 4.25.0 request latency

Medians in microseconds from eight alternating release-build process pairs per comparison on CPU 14. The integrated build is the baseline for both comparisons. Its row uses its samples paired with the fork. Upstream and fork rows each use their own paired runs.

| Caller | Revision | GET | Form POST | JSON POST |
|---|---|---:|---:|---:|
| Matched data unread | Upstream 0.13.3 | 63.1 | 75.6 | 84.0 |
| Matched data unread | All eight PRs | 49.3 | 61.8 | 71.7 |
| Matched data unread | Fork | 38.7 | 48.3 | 56.5 |
| Matched data read after each request | Upstream 0.13.3 | 67.3 | 79.6 | 89.0 |
| Matched data read after each request | All eight PRs | 53.1 | 66.3 | 75.5 |
| Matched data read after each request | Fork | 56.3 | 65.1 | 74.4 |

## Reproducing the workloads

Copy the two Rust files in this directory to the checkout's `examples/` directory. Build both with the same Rust toolchain, lockfile, release profile and CPU affinity on each side.

```sh
CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --locked --release --example focused_latency --example release_latency
FOCUS=tx taskset -c 12 target/release/examples/focused_latency 5000
FOCUS=url taskset -c 12 target/release/examples/focused_latency 5000
FOCUS=filename taskset -c 12 target/release/examples/focused_latency 10000
CRS_BENCH_DIR=/path/to/crs-4.25.0 READ=none taskset -c 12 target/release/examples/release_latency 2200
CRS_BENCH_DIR=/path/to/crs-4.25.0 READ=end taskset -c 12 target/release/examples/release_latency 2200
```

The CRS checkout must be at `aabf675fcfc5e489b424b844e6c9f1b39802df69`. Each process loads 698 rules and checks both clean transactions and a denied method before timing. The focused tests time a whole transaction through the request-header phase. The full CRS fixtures include headers, body and logging. Every number is a process mean in microseconds per request. Reported percentage changes are medians of paired differences divided by the baseline for that pair. Process order alternates within each comparison.

## Samples

- `focus-fresh-base-12.json` compares #142 and #143 individually with upstream in ten pairs on CPU 12. `focus-main-14.json` repeats the tests with #137–140 on both sides on CPU 14.
- `focus-path.json` compares #141 with upstream in twelve pairs on CPU 12.
- `standalone.json` compares each new branch with an unmodified upstream build on CPU 12. `confirm-14.json` and `incremental.json` use #137–140 as the baseline on CPU 14. `all` includes all seven patches. `rule-width`, `key-prefix` and `capture-keys` are local experiments.
- `incremental-eight.json` adds #144 to all seven earlier PRs. `standalone-width.json` compares #144 and a second unmodified upstream build with upstream 0.13.3.
- `tx-variants.json` compares two alternative TX regex implementations with the first revision of #142, on top of #137–140. `tx-helper` is the implementation in the final revision. `focus-fresh-base-12-tx.json` and `helper-standalone.json` measure that revision on standalone upstream. `with-tx.json` adds it to all seven other PRs.
- `final-gap.json` compares upstream and the fork with the final eight-PR build. In both comparisons `main` is the eight-PR build. `helper-eight.json` isolates the final #142 revision from its first revision within that build.
- `current-main.json` and `gap-eight.json` use the first revision of #142. `gap-eight.json` compares the fork with all eight PRs on CPU 14.
- `gap.json` compares the fork to all seven patches on CPU 12. In this file `main` denotes the seven-PR build. Suffixes `none` and `end` describe when the caller reads matched data.

The URL validator in #143 is behind a PL2 rule in stock CRS on the form-body path. Use the focused URI cases for attribution. Small full-suite timing differences can reflect code layout, and percentages from separate patches cannot be added.
