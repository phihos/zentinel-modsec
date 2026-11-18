# Filename and header selection on OWASP CRS 4.25.0

Engine `c14c323` follows fork checkpoint `e0579b6`. Each phase summarizes the decoded filename and up to two frequently selected request headers. A rule skips an absent header or a positive static regex or phrase target whose input cannot reach the required match length. Counts, unknown bounds, and targets outside the compiled prefix retain their usual evaluation. Three further changes prepare literal TX defaults in insertion order, store each audit rule location in one machine word, and reserve space for a macro prefix and value together. [Source comparison](source-binding.json)

## Full-CRS inspection latency

The benchmark from upstream PR #69 loaded the pinned 698-rule CRS 4.25.0 configuration with blocking enabled. It checked the allowed transactions and a denied method before timing complete request creation, header and body inspection, logging, and drop. Eight Criterion process pairs alternated order on CPU 14 of an AMD Ryzen 7 5700X3D, with 24 samples per workload per process and the default Rust detector. Before and after are medians of the process means. Paired changes are the median of the eight within-pair percentage changes. A second run interleaved warmed workers every 96 requests and measured both wall and thread CPU time. [Criterion](bench/criterion/receipt.json) · [Interleaved workers](bench/interleaved/receipt.json) · [Raw samples](samples.zip)

| Workload | Before, µs | After, µs | Paired change | Faster pairs | Interleaved wall change | CPU time change |
|---|---:|---:|---:|---:|---:|---:|
| GET | 49.1 | 46.6 | -7.8% | 7/8 | -8.1% | -8.3% |
| Form POST | 59.8 | 57.4 | -6.1% | 6/8 | -7.5% | -7.2% |
| Nested JSON POST | 72.3 | 71.8 | -2.8% | 6/8 | -4.9% | -4.7% |

## Larger inputs and tail latency

The new length checks fall back on long values, bytes outside their supported alphabets, or headers with more than 32 values. Six additional allowed requests used the same 698 rules. Each row summarizes six pairs of warmed processes alternating every 32 transactions. [Argument workloads](bench/edge-full.rs) · [Filename and header workloads](bench/additional-full.rs) · [Argument measurements](bench/varied/receipt.json) · [Filename and header measurements](bench/additional/receipt.json)

| Workload | Before, µs | After, µs | Paired change | Faster pairs |
|---|---:|---:|---:|---:|
| GET with a 65-byte argument | 71.5 | 69.2 | -3.6% | 6/6 |
| Form with 33 fields | 229.1 | 224.8 | -2.1% | 5/6 |
| JSON containing a UTF-8 value, space and slash | 118.9 | 116.6 | -2.3% | 5/6 |
| GET with a 110-byte decoded path | 53.7 | 53.6 | -0.8% | 4/6 |
| Form with a browser User-Agent over 64 bytes | 66.6 | 63.9 | -3.8% | 6/6 |
| JSON POST to a percent-encoded UTF-8 path | 80.0 | 80.6 | +0.9% | 1/6 |

The historical 706-rule configuration ran 24 mixed fixtures. Each of six process pairs per backend timed 2,400 requests per process. The table shows the median of the six process quantiles. [Mixed request samples and worker hashes](bench/mixed-final/receipt.json)

| Detector | p50 before → after, µs | Faster pairs | p99 before → after, µs | Faster pairs |
|---|---:|---:|---:|---:|
| Rust | 119.7 → 115.8 | 6/6 | 155.3 → 150.5 | 5/6 |
| Optional C | 113.1 → 110.5 | 6/6 | 152.5 → 153.5 | 3/6 |

The first run split the optional C p99 comparison three pairs apiece. A second run used the same binaries and 12 new pairs per backend, starting seven fixtures later in the rotation. The table includes all 18 pairs from both runs. [Repeat measurement](bench/mixed-repeat/receipt.json) · [Raw samples](samples.zip)

| Detector | p99 before → after, µs | Paired change | Faster pairs |
|---|---:|---:|---:|
| Rust | 156.0 → 152.8 | -2.1% | 14/18 |
| Optional C | 146.7 → 146.4 | -0.1% | 10/18 |

## Memory and ruleset loading

Fresh ruleset loading measured 267.3 → 272.7 ms in twelve process pairs (+1.8% paired). [Cold loads](bench/load-results.json)

The cold ruleset retained 31,506,934 → 31,516,957 live allocator bytes before the first request, an increase of 10,023 bytes (0.032%). All seven processes per revision recorded the same values. Dropping the ruleset returned both versions to the same live byte count. [Live heap measurement](ruleset-heap/receipt.json)

Prepared TX key/value pairs and header indices are retained once per ruleset. Each transaction still has its own TX map and hash seed. These allocation totals count requested bytes, including reallocations, from creating through dropping one request with audit getters unread. The receipt also covers reading audit data during and after inspection. [Request allocations](verification/allocations.json)

| Workload | Allocation calls before → after | Allocated bytes before → after |
|---|---:|---:|
| GET | 136 → 133 | 26,644 → 24,543 |
| Form POST | 197 → 191 | 30,290 → 28,135 |
| Nested JSON POST | 223 → 217 | 29,882 → 27,759 |

## Correctness

Formatting and strict Clippy passed. The Rust build passed 693 tests and the optional C build passed 695. Both retained all 5,187 native stage outcomes, all 22 blocking traces and all 24 complete audit records. On the pinned external CRS suite both matched Coraza case for case, including 4,655 passes, 17 failures and one fixture error. The upstream detector corpus passed. [Verification](verification/summary.json)

The regex comparison covered 20,044,080 expression/input pairs. The phrase comparison covered 3,710,930 capture-mode cases and preserved all 12,866 positive stages. The two comparisons independently verified the discarded filename and header targets. Four workers sharing a ruleset also matched serial execution and the previous engine byte for byte across all five phases, including mid-request audit reads. A header inserted between phases became visible to the next phase. [Regex and transformations](integrated-operators/2d323921fc2c/receipt.json) · [Phrases](phase-phrase-differential/2d323921fc2c/receipt.json) · [Concurrent transactions](final-engine-equivalence/receipt.json) · [Header phase test](final-engine-equivalence/header-phases.rs)

An audit stress check matched 301 rules in each of five phases and verified the ordered rule IDs and match data for early and late readers on both backends. [Audit check](audit-locations/2d323921.json)

## Reproduce the main benchmark

Use Rust 1.96.1 and a clean checkout of OWASP CRS 4.25.0 at `aabf675fcfc5e489b424b844e6c9f1b39802df69`. Run the following from each benchmark revision, `25f1d65f` and `2d323921`, after copying the benchmark lockfile to the checkout root as `Cargo.lock`. Set `CRS_BENCH_DIR` to the absolute CRS checkout path. Repeat eight times, alternating which revision runs first. [Benchmark lockfile](bench/Cargo.lock)

```sh
cargo bench --locked --bench modsec_bench -- full_crs --warm-up-time 0.3 --measurement-time 1 --sample-size 24 --nresamples 3000 --noplot
```
