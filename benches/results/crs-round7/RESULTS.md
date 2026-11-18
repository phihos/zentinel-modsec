# Full CRS latency on ordinary requests and large forms

Compared with the previous fork checkpoint `b2f41fe9`, revision `181fbca0` caches the maximum length and character class of argument names and values across phases. That lets rules skip collections whose fields cannot match even past the previous 128-field or 4 KiB cutoff. Rules with phase-independent targets also reuse a precomputed mask. For simple anchored TX key selectors, the engine compares already-folded ASCII prefixes directly and uses the original regex for Unicode prefixes. [Engine revisions](source-binding.json)

## Ordinary traffic

The benchmark loads all 698 rules in OWASP CRS 4.25.0, checks allowed requests and a denied method, then times transaction creation, header and body inspection, logging and drop with the default Rust detector. Eight pairs of fresh Criterion processes alternated which revision ran first on CPU 14 of an AMD Ryzen 7 5700X3D. Before and after are medians of process means. Percentage changes are medians of within-pair changes. A second comparison interleaved warmed workers and recorded both elapsed and thread CPU time. [Criterion](bench/criterion/receipt.json) · [Interleaved workers](bench/interleaved/receipt.json) · [Raw samples](samples.zip)

| Workload | Before, µs | After, µs | Paired change | Faster pairs | Interleaved wall | Interleaved CPU |
|---|---:|---:|---:|---:|---:|---:|
| GET | 39.9 | 37.6 | -5.4% | 7/8 | -4.7% | -4.5% |
| Form POST | 50.1 | 47.5 | -5.1% | 8/8 | -4.0% | -4.2% |
| Nested JSON POST | 59.2 | 56.4 | -5.2% | 8/8 | -3.0% | -3.1% |

## Large forms and other request shapes

Six pairs of warmed workers alternated revisions on the same CPU. Each fixture checks its blocking decision and expected matched rule IDs. The 257-field UTF-8 case places the only non-ASCII value last. That value makes the ASCII width shortcut inapplicable to the values in the collection. [Boundary forms](bench/limits-full.rs) · [Larger forms](bench/large-full.rs) · [Other arguments](bench/edge-full.rs) · [Paths and headers](bench/additional-full.rs) · [Denial and upload](bench/coverage-full.rs)

| Workload | Before, µs | After, µs | Paired wall change | Faster pairs | CPU change |
|---|---:|---:|---:|---:|---:|
| [Form with 128 short fields](bench/limits/receipt.json) | 310.1 | 301.1 | -1.8% | 4/6 | -2.5% |
| [Form with 129 short fields](bench/limits/receipt.json) | 700.7 | 295.6 | -58.0% | 6/6 | -58.1% |
| [Form with 65 fields of 64 bytes (name + value)](bench/limits/receipt.json) | 757.0 | 473.3 | -37.4% | 6/6 | -37.8% |
| [Form with 257 distinct fields](bench/large/receipt.json) | 1315.3 | 581.4 | -55.8% | 6/6 | -55.9% |
| [Form with 384 values under one case-folded key](bench/large/receipt.json) | 1751.7 | 837.0 | -52.4% | 6/6 | -52.3% |
| [Form with 257 fields and a final UTF-8 value](bench/large/receipt.json) | 1359.4 | 995.7 | -27.4% | 6/6 | -27.3% |
| [GET with a 65-byte argument](bench/varied/receipt.json) | 67.7 | 65.3 | -3.1% | 6/6 | -3.1% |
| [Form with 33 fields](bench/varied/receipt.json) | 136.1 | 132.2 | -2.6% | 6/6 | -2.6% |
| [JSON containing a UTF-8 value, space and slash](bench/varied/receipt.json) | 111.1 | 109.6 | -1.3% | 6/6 | -1.3% |
| [GET with a 110-byte decoded path](bench/additional/receipt.json) | 51.8 | 49.7 | -3.7% | 6/6 | -3.4% |
| [Form with a User-Agent over 64 bytes](bench/additional/receipt.json) | 62.0 | 59.4 | -4.3% | 6/6 | -4.3% |
| [JSON sent to a UTF-8 path](bench/additional/receipt.json) | 73.7 | 71.6 | -3.0% | 6/6 | -2.9% |
| [Denied PATCH](bench/coverage/receipt.json) | 35.9 | 34.5 | -4.0% | 6/6 | -4.1% |
| [GET with 33 additional headers](bench/coverage/receipt.json) | 86.8 | 83.6 | -3.7% | 6/6 | -3.7% |
| [Multipart POST with a text file](bench/coverage/receipt.json) | 59.7 | 57.6 | -3.4% | 6/6 | -3.3% |

The [resident worker](bench/resident.rs) wraps the same fixtures and measures elapsed and thread CPU time per batch. [Fixture and binary hashes](fixture-sources.json)

## Indexed argument lookups

A single rule looked up one named field after the engine had parsed 8,192 query parameters. The matched header phase took 2.61 → 108.57 → 2.58 µs on the previous checkpoint, an intermediate candidate that scanned unrelated fields, and the final code. Including parsing and destruction, the same request took 1,379.62 → 1,455.36 → 1,413.16 µs. Across the match, miss and absent-key cases, the final code spent 2.4–2.6% longer on the complete request than the previous checkpoint, mostly in parsing. The final ruleset requests a width summary only when at least one eligible selector would enumerate a collection. A phase containing such a selector can still pay for one initial scan even when later control flow skips that rule. [Fixture](sparse-phase/sparse.rs) · [Quiet repeat](sparse-phase/repeat-receipt.json) · [Repeat block means](sparse-phase/repeat-raw.json) · [Initial run](sparse-phase/receipt.json)

## Mixed traffic

The historical 706-rule configuration ran 24 mixed fixtures and 2,400 requests per process. Six counterbalanced pairs were followed by 12 pairs with a shifted starting fixture. The table shows medians of the 18 process quantiles and the median paired p99 change. [First six pairs](bench/mixed-final/receipt.json) · [Remaining twelve](bench/mixed-repeat/receipt.json)

| Detector | p50 before → after, µs | p99 before → after, µs | Paired p99 change | Faster p99 pairs |
|---|---:|---:|---:|---:|
| Rust | 106.6 → 106.3 | 148.8 → 150.6 | +0.2% | 9/18 |
| Optional C | 98.9 → 96.5 | 142.0 → 139.4 | -1.8% | 15/18 |

## Memory and ruleset loading

The compiled CRS ruleset retained 31,539,765 → 31,539,765 live allocator bytes before its first request (+0 bytes). Fresh ruleset loading took 274.6 → 274.1 ms across twelve process pairs (-0.2% paired). [Ruleset heap](ruleset-heap-181fbca0/receipt.json) · [Load times](bench/load-results.json)

The inline transaction object grew from 2,408 to 2,520 bytes on x86-64. Its request-data member grew from 1,504 to 1,608 bytes. The per-rule dispatch record stayed at 168 bytes. [Rust type layouts](rust-layouts/181fbca01bf3/receipt.json)

Allocation counters cover request creation through drop. These rows use unread audit getters. The receipt also covers audit reads during and after inspection. [Request allocations](verification/allocations.json)

| Workload | Allocation calls before → after | Requested bytes before → after |
|---|---:|---:|
| GET | 116 → 116 | 23,445 → 23,445 |
| Form POST | 164 → 164 | 26,025 → 26,025 |
| Nested JSON POST | 190 → 190 | 25,683 → 25,683 |

## Rule behavior

Formatting and strict Clippy passed. The default build passed 700 all-target tests and the optional C build passed 702. Both preserved all 5,187 native stage outcomes, 22 blocking traces and 24 complete audit records. The external CRS suite matched Coraza case for case, including its 4,655 passes, 17 failures and one fixture error. The reference detector corpus passed. [Verification](verification/summary.json)

Independent comparisons checked 21,239,508 regex/input pairs, 3,932,762 phrase/capture cases and 488,400 width decisions after request data changed. All 336 last-field matches survived. Two detector builds also compared 8,284 opaque or folded TX keys across 26 selectors. A separate corpus compared 1,262,625 TX selection decisions with an independent regex scan. [Regex](integrated-operators/181fbca01bf3/receipt.json) · [Phrases](phase-phrase-differential/181fbca01bf3/receipt.json) · [Collections](collection-boundary/181fbca01bf3/receipt.json) · [TX selectors](tx-prefix-differential/181fbca0.json) · [Independent TX decisions](tx-selector-differential/181fbca01bf3/receipt.json)

Four workers sharing one ruleset produced the same ordered output as the baseline across five phases and two audit-read schedules. Separate comparisons checked form boundaries, engine-mode changes, early and late audit reads, and 1,680 dynamic `@within` cases. [Concurrent execution](final-engine-equivalence/receipt.json) · [Form boundaries](final-engine-equivalence/bound-fields-receipt.json) · [Engine modes](final-engine-equivalence/control-off-receipt.json) · [Audit reads](verification/audit-reads.json) · [Within operands](within-differential/181fbca0.json) · [Within keys](within-key-differential/181fbca0.json)

## Reproduce

Check out each benchmark revision, `b2f41fe9133547b7e4e5f012c694193e7b064c8c` and `181fbca01bf3142fc006fba61b4241165c2cd00b`. Copy the [measurement lockfile](bench/Cargo.lock) to its root as `Cargo.lock`. Set `CRS_BENCH_DIR` to the absolute path of a clean OWASP CRS checkout at `aabf675fcfc5e489b424b844e6c9f1b39802df69`. Measurements used rustc 1.96.1 on x86-64 Linux. Alternate the order of the two revisions across eight pairs.

```sh
cargo bench --locked --bench modsec_bench -- full_crs --warm-up-time 0.3 --measurement-time 1 --sample-size 24 --nresamples 3000 --noplot
```

To exercise one of the supplementary fixtures with Criterion, copy its linked Rust file over `benches/modsec_bench/full_crs.rs` in each benchmark checkout and rerun the same command. The supplementary timing tables above used interleaved resident workers.
