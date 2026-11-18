# Rule target selection and TX searches on OWASP CRS 4.25.0

Engine `ece387f` follows fork checkpoint `6f35d92`. An exact `@within %{TX.member}` operand can borrow the current transaction value while scanning candidates. After a match, subsequent evaluations see updated TX state. Rules without transformations evaluate the original input once. The engine also skips groups of rules whose targets are empty, avoids lookups for absent upload fields and headers, and uses tighter minimum match lengths for dotted names such as nested JSON keys. A phase checks for an engine-mode change after a matched rule runs controls. [Source comparison](source-binding.json)

## Full-CRS inspection latency

The benchmark from upstream PR #69 loaded the pinned 698-rule CRS 4.25.0 configuration with blocking enabled. It checked the allowed transactions and a denied method before timing complete request creation, header and body inspection, logging, and drop. Sixteen Criterion process pairs alternated order on CPU 14 of an AMD Ryzen 7 5700X3D, with 24 samples per workload per process and the default Rust detector. Before and after are medians of the process means. Paired changes are the median of the sixteen within-pair percentage changes. The first eight pairs overlapped correctness checks. Timing variability prompted another eight pairs after verification. An independent run interleaved warmed workers every 96 requests and measured both wall and thread CPU time. [First eight pairs](bench/criterion/receipt.json) · [Second eight pairs](bench/criterion-repeat/receipt.json) · [Combined results](bench/criterion-combined.json) · [Interleaved workers](bench/interleaved/receipt.json) · [Raw samples](samples.zip)

| Workload | Before, µs | After, µs | Paired change | Faster pairs | Interleaved wall change | CPU time change |
|---|---:|---:|---:|---:|---:|---:|
| GET | 45.1 | 41.0 | -6.1% | 13/16 | -5.9% | -6.2% |
| Form POST | 53.4 | 50.8 | -4.9% | 14/16 | -3.3% | -3.3% |
| Nested JSON POST | 69.3 | 60.4 | -9.7% | 14/16 | -10.6% | -10.5% |

## Larger inputs and tail latency

The same 698-rule configuration ran nine additional requests, alternating warmed workers every 32 inspections across six pairs per workload. The last three exercise a denied HTTP method, a request above the 32-header lookup limit, and a request with an actual uploaded file. The benchmark checks the expected blocking decision before timing each workload. [Argument workloads](bench/edge-full.rs) · [Filename and header workloads](bench/additional-full.rs) · [Denial, headers and upload](bench/coverage-full.rs) · [Argument timings](bench/varied/receipt.json) · [Path timings](bench/additional/receipt.json) · [Denial and upload timings](bench/coverage/receipt.json)

| Workload | Before, µs | After, µs | Paired change | Faster pairs |
|---|---:|---:|---:|---:|
| GET with a 65-byte argument | 69.0 | 67.9 | -2.2% | 6/6 |
| Form with 33 fields | 227.6 | 233.1 | +2.6% | 0/6 |
| JSON containing a UTF-8 value, space and slash | 117.4 | 112.7 | -4.5% | 6/6 |
| GET with a 110-byte decoded path | 53.6 | 51.5 | -4.2% | 6/6 |
| Form with a browser User-Agent over 64 bytes | 64.3 | 61.4 | -4.5% | 6/6 |
| JSON POST to a percent-encoded UTF-8 path | 81.0 | 73.8 | -9.1% | 6/6 |
| Denied PATCH to /cart | 38.2 | 35.7 | -6.0% | 6/6 |
| GET with 33 additional headers | 89.3 | 86.3 | -2.9% | 6/6 |
| Multipart POST with a text file | 60.8 | 59.2 | -2.4% | 6/6 |

The historical 706-rule configuration used 24 mixed request fixtures and 2,400 transactions per process. For each detector, six process pairs alternated order, followed by 12 more with the starting fixture shifted by seven. These are medians of the 18 process quantiles. [First six pairs](bench/mixed-final/receipt.json) · [Remaining twelve pairs](bench/mixed-repeat/receipt.json) · [Raw timings](samples.zip)

| Detector | p50 before → after, µs | Faster pairs | p99 before → after, µs | Faster pairs | Paired p99 change |
|---|---:|---:|---:|---:|---:|
| Rust | 117.5 → 107.3 | 18/18 | 156.1 → 150.3 | 13/18 | -4.3% |
| Optional C | 110.7 → 98.1 | 18/18 | 154.3 → 142.7 | 14/18 | -9.1% |

## Memory and ruleset loading

Fresh ruleset loading measured 275.5 → 278.2 ms in twelve process pairs (+1.0% paired). [Cold loads](bench/load-results.json)

The cold ruleset retained 31,516,957 → 31,539,765 live allocator bytes before the first request (+22,808 bytes, +0.072%). [Live heap measurement](ruleset-heap/receipt.json)

These allocation totals count requested bytes, including reallocations, from creating through dropping one request with audit getters unread. The receipt also covers reading audit data during and after inspection. [Request allocations](verification/allocations.json)

| Workload | Allocation calls before → after | Allocated bytes before → after |
|---|---:|---:|
| GET | 133 → 116 | 24,543 → 23,445 |
| Form POST | 191 → 164 | 28,135 → 26,025 |
| Nested JSON POST | 217 → 190 | 27,759 → 25,683 |

## Correctness

Formatting and strict Clippy passed. The Rust build passed 697 tests and the optional C build passed 699. Both retained all 5,187 native stage outcomes, all 22 blocking traces and all 24 complete audit records. On the pinned external CRS suite both matched Coraza case for case, including 4,655 passes, 17 failures and one fixture error. The upstream detector corpus passed. [Verification](verification/summary.json)

The regex comparison covered 21,239,508 expression/input pairs and checked 156,256 exclusions specific to dotted input. The phrase comparison covered 3,932,762 capture-mode cases and preserved all 12,866 positive stages. The two comparisons independently verified the discarded filename and header targets. Four workers sharing a ruleset also matched serial execution and the previous engine byte for byte across all five phases, including mid-request audit reads. [Regex and transformations](integrated-operators/bf51bbc925c9/receipt.json) · [Phrases](phase-phrase-differential/bf51bbc925c9/receipt.json) · [Concurrent transactions](qualified-engine-equivalence/receipt.json)

Two additional comparisons checked all audit and TX results across 1,680 dynamic `@within` cases, including binary values, TX writes after a match, and missing, empty, or case-folded keys. [Operand and capture checks](within-differential/bf51bbc9.json) · [Key checks](within-key-differential/bf51bbc9.json)

Eight additional cases checked the timing of engine-mode changes in chains, across skipped rules, and during logging. Both backends matched the previous engine with and without diagnostics. [Control action comparison](qualified-engine-equivalence/control-off-receipt.json)

Early and late audit reads matched the baseline on all 144 fixture and read-schedule combinations per backend. [Audit read schedules](verification/audit-reads.json)

## Reproduce the main benchmark

Use Rust 1.96.1 and a clean checkout of OWASP CRS 4.25.0 at `aabf675fcfc5e489b424b844e6c9f1b39802df69`. Run the following from each benchmark revision, `2d323921` and `bf51bbc9`, after copying the benchmark lockfile to the checkout root as `Cargo.lock`. Set `CRS_BENCH_DIR` to the absolute CRS checkout path. Repeat sixteen times, alternating which revision runs first. [Benchmark lockfile](bench/Cargo.lock)

```sh
cargo bench --locked --bench modsec_bench -- full_crs --warm-up-time 0.3 --measurement-time 1 --sample-size 24 --nresamples 3000 --noplot
```
