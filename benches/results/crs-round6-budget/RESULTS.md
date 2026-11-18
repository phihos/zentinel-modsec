# Bounded argument classification and full-CRS request latency

Engine `93870ea` is compared directly with `6f35d92`, the fork checkpoint at the start of this optimization round. It includes the target selection changes measured in the previous checkpoint plus a bounded scan for larger argument collections. An exact `@within %{TX.member}` operand can borrow the current transaction value while scanning candidates. After a match, subsequent evaluations see updated TX state. Rules without transformations evaluate the original input once. The engine also skips groups of rules whose targets are empty, avoids lookups for absent upload fields and headers, and uses tighter minimum match lengths for dotted names such as nested JSON keys. A phase checks for an engine-mode change after a matched rule runs controls. [Source comparison](source-binding.json)

## Full-CRS inspection latency

The benchmark from upstream PR #69 loaded the pinned 698-rule CRS 4.25.0 configuration with blocking enabled. It checked the allowed transactions and a denied method before timing complete request creation, header and body inspection, logging, and drop. Eight Criterion process pairs alternated order on CPU 14 of an AMD Ryzen 7 5700X3D, with 24 samples per workload per process and the default Rust detector. Before and after are medians of the process means. Paired changes are the median of the eight within-pair percentage changes. An independent run interleaved warmed workers every 96 requests and measured both wall and thread CPU time. [Criterion results](bench/criterion/receipt.json) · [Interleaved workers](bench/interleaved/receipt.json) · [Raw samples](samples.zip)

| Workload | Before, µs | After, µs | Paired change | Faster pairs | Interleaved wall change | CPU time change |
|---|---:|---:|---:|---:|---:|---:|
| GET | 41.5 | 39.4 | -4.6% | 7/8 | -3.8% | -3.8% |
| Form POST | 51.9 | 49.7 | -4.0% | 7/8 | -1.9% | -1.5% |
| Nested JSON POST | 65.0 | 58.9 | -9.4% | 8/8 | -8.8% | -8.7% |

## Larger inputs and tail latency

The same 698-rule configuration ran twelve additional requests, alternating warmed workers every 32 inspections (16 for the three budget-limit fixtures) across six pairs per workload. The fixtures exercise a denied HTTP method, a request above the 32-header lookup limit, a request with an actual uploaded file, and requests at both argument-budget limits. The benchmark checks the expected blocking decision before timing each workload. [Argument workloads](bench/edge-full.rs) · [Filename and header workloads](bench/additional-full.rs) · [Denial, headers and upload](bench/coverage-full.rs) · [Budget-limit workloads](bench/limits-full.rs) · [Limit timings](bench/limits/receipt.json) · [Argument timings](bench/varied/receipt.json) · [Path timings](bench/additional/receipt.json) · [Denial and upload timings](bench/coverage/receipt.json)

| Workload | Before, µs | After, µs | Paired change | Faster pairs |
|---|---:|---:|---:|---:|
| GET with a 65-byte argument | 75.3 | 74.6 | -2.5% | 5/6 |
| Form with 33 fields | 241.1 | 144.8 | -39.4% | 6/6 |
| JSON containing a UTF-8 value, space and slash | 124.7 | 119.9 | -2.9% | 5/6 |
| GET with a 110-byte decoded path | 55.9 | 54.2 | -2.8% | 5/6 |
| Form with a browser User-Agent over 64 bytes | 69.2 | 66.5 | -4.0% | 6/6 |
| JSON POST to a percent-encoded UTF-8 path | 83.9 | 77.8 | -7.1% | 6/6 |
| Denied PATCH to /cart | 41.4 | 38.7 | -4.6% | 6/6 |
| GET with 33 additional headers | 93.9 | 91.9 | -1.8% | 5/6 |
| Multipart POST with a text file | 62.9 | 63.8 | -0.3% | 3/6 |
| Form with 128 short fields | 620.1 | 287.0 | -53.7% | 6/6 |
| Form with 129 short fields | 626.7 | 662.8 | +7.0% | 0/6 |
| Form with 65 fields of 64 bytes each | 715.2 | 736.8 | +1.6% | 0/6 |

The previous 32-field cutoff made the 33-field form 2.6% slower at the intermediate revision. Each phase now shares a 4,096-byte budget across GET and POST and charges each member at least 32 bytes. This covers up to 128 small fields. Exceeding either limit restores normal rule evaluation for the complete collection. Comparing the two revisions directly, the 33-field form went from 233.2 to 135.1 µs (-41.9% paired, 6/6 faster). [Intermediate report](../crs-round6/RESULTS.md) · [Isolated comparison](bench/budget-increment/receipt.json)

Against that same intermediate revision, the budget change alone measured -54.5% on 128 short fields, +5.4% on 129 short fields, and -2.5% on 65 fields of 64 bytes. The last two exceed the scan budget. [Incremental limit timings](bench/limit-increment/receipt.json)

The historical 706-rule configuration used 24 mixed request fixtures and 2,400 transactions per process. For each detector, six process pairs alternated order, followed by 12 more with the starting fixture shifted by seven. These are medians of the 18 process quantiles. [First six pairs](bench/mixed-final/receipt.json) · [Remaining twelve pairs](bench/mixed-repeat/receipt.json) · [Raw timings](samples.zip)

| Detector | p50 before → after, µs | Faster pairs | p99 before → after, µs | Faster pairs | Paired p99 change |
|---|---:|---:|---:|---:|---:|
| Rust | 116.5 → 106.3 | 18/18 | 155.9 → 150.6 | 14/18 | -1.6% |
| Optional C | 108.9 → 98.9 | 18/18 | 146.6 → 142.2 | 16/18 | -3.6% |

## Memory and ruleset loading

Fresh ruleset loading measured 272.9 → 275.7 ms in twelve process pairs (+1.2% paired). [Cold loads](bench/load-results.json)

The cold ruleset retained 31,516,957 → 31,539,765 live allocator bytes before the first request (+22,808 bytes, +0.072%). [Live heap measurement](ruleset-heap/receipt.json)

These allocation totals count requested bytes, including reallocations, from creating through dropping one request with audit getters unread. The receipt also covers reading audit data during and after inspection. [Request allocations](verification/allocations.json)

| Workload | Allocation calls before → after | Allocated bytes before → after |
|---|---:|---:|
| GET | 133 → 116 | 24,543 → 23,445 |
| Form POST | 191 → 164 | 28,135 → 26,025 |
| Nested JSON POST | 217 → 190 | 27,759 → 25,683 |

## Correctness

Formatting and strict Clippy passed. The Rust build passed 697 tests and the optional C build passed 699. Both retained all 5,187 native stage outcomes, all 22 blocking traces and all 24 complete audit records. On the pinned external CRS suite both matched Coraza case for case, including 4,655 passes, 17 failures and one fixture error. The upstream detector corpus passed. [Verification](verification/summary.json)

The regex comparison covered 21,239,508 expression/input pairs and checked 156,256 exclusions specific to dotted input. The phrase comparison covered 3,932,762 capture-mode cases and preserved all 12,866 positive stages. The two comparisons independently verified the discarded filename and header targets. Four workers sharing a ruleset also matched serial execution and the previous engine byte for byte across all five phases, including mid-request audit reads. [Regex and transformations](integrated-operators/b2f41fe91335/receipt.json) · [Phrases](phase-phrase-differential/b2f41fe91335/receipt.json) · [Concurrent transactions](qualified-engine-equivalence/receipt.json)

Two additional comparisons checked all audit and TX results across 1,680 dynamic `@within` cases, including binary values, TX writes after a match, and missing, empty, or case-folded keys. [Operand and capture checks](within-differential/b2f41fe9.json) · [Key checks](within-key-differential/b2f41fe9.json)

Eight additional cases checked the timing of engine-mode changes in chains, across skipped rules, and during logging. Both backends matched the previous engine with and without diagnostics. [Control action comparison](qualified-engine-equivalence/control-off-receipt.json)

Early and late audit reads matched the baseline on all 144 fixture and read-schedule combinations per backend. [Audit read schedules](verification/audit-reads.json)

A separate check used 96 complete argument collections at 32, 33, 127, 128, and 129 members and immediately below, at, and above 4,096 bytes. It checked every excluded target against the original members and transformation stages, verified 16,752 over-budget rule masks, and preserved all last-field matches. An end-to-end check also compared baseline and candidate audit records on both backends for 12 forms at the field and byte limits. [Collection checks](collection-boundary/b2f41fe91335/receipt.json) · [End-to-end checks](qualified-engine-equivalence/bound-fields-receipt.json)

## Reproduce the main benchmark

Use Rust 1.96.1 and a clean checkout of OWASP CRS 4.25.0 at `aabf675fcfc5e489b424b844e6c9f1b39802df69`. Run the following from each benchmark revision, `2d323921` and `b2f41fe9`, after copying the benchmark lockfile to the checkout root as `Cargo.lock`. Set `CRS_BENCH_DIR` to the absolute CRS checkout path. Repeat eight times, alternating which revision runs first. [Benchmark lockfile](bench/Cargo.lock)

```sh
cargo bench --locked --bench modsec_bench -- full_crs --warm-up-time 0.3 --measurement-time 1 --sample-size 24 --nresamples 3000 --noplot
```
