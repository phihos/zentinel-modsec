# Query and form parsing with the full OWASP CRS

Compared with fork checkpoint `181fbca0`, revision `20db5d8b` parses plain query and URL-encoded form fields without decoding each component. For long inputs, the parser ends each group at the first field separator at or after 1,024 bytes. Empty groups and duplicate field spellings retain their original behavior. A group with percent escapes, plus signs or opaque bytes uses the byte decoder. Prepared TX defaults now use bulk insertion into each transaction’s independently seeded map. Byte-range, URL-encoding and UTF-8 rules can skip a group of short fields when its known character class proves every byte valid. Negated and dynamic rules keep their existing evaluation path. [Engine revisions](source-binding.json)

## 8,192 fields with all 698 rules

A form POST contained 8,192 distinct fields. Three workloads used identical decoded values, sent as plain text, with an escape in the final field, or with an escape in every field. The worker checked that CRS allowed each request and recorded the expected rule IDs. Across eight process pairs, each worker warmed up on four requests and then alternated in batches of two. [Fixture](bench/8192-full.rs) · [Raw wall and CPU batches](bench/full-large/receipt.json)

| Form POST | Before, ms | After, ms | Paired wall change | CPU change | Faster pairs |
|---|---:|---:|---:|---:|---:|
| Plain fields | 22.99 | 22.31 | -2.9% | -2.8% | 8/8 |
| One late escape | 22.86 | 22.36 | -2.7% | -2.6% | 8/8 |
| Every value escaped | 23.42 | 22.97 | -2.0% | -2.0% | 8/8 |

## Ordinary traffic

The benchmark loads all 698 rules in OWASP CRS 4.25.0, checks allowed requests and a denied method, then times transaction creation, header and body inspection, logging and drop with the default Rust detector. Eight pairs of fresh Criterion processes alternated which revision ran first on CPU 14 of an AMD Ryzen 7 5700X3D. Before and after are medians of process means. Percentage changes are medians of within-pair changes. A second comparison interleaved warmed workers and recorded both elapsed and thread CPU time. [Criterion](bench/criterion/receipt.json) · [Interleaved workers](bench/interleaved/receipt.json) · [Raw samples](samples.zip)

| Workload | Before, µs | After, µs | Paired change | Faster pairs | Interleaved wall | Interleaved CPU |
|---|---:|---:|---:|---:|---:|---:|
| GET | 42.7 | 41.7 | -1.2% | 5/8 | +1.1% | +0.9% |
| Form POST | 53.6 | 52.5 | -5.5% | 5/8 | -1.5% | -0.9% |
| Nested JSON POST | 64.7 | 63.2 | -3.0% | 5/8 | +1.0% | +0.3% |

A further 12 interleaved pairs measured paired wall changes of +0.4%, -0.1%, +0.4% for GET, form POST and nested JSON POST. The three comparisons ran on a shared host. The spread gives an indication of run-to-run variation. [Repeat timings](bench/interleaved-repeat/receipt.json) · [CPU activity](bench/repeat-load.json)

## Large forms and other request shapes

Six pairs of warmed workers alternated revisions on the same CPU. Each fixture checks its blocking decision and expected matched rule IDs. The 257-field UTF-8 case places the only non-ASCII value last. That value makes the ASCII width shortcut inapplicable to the values in the collection. [Boundary forms](bench/limits-full.rs) · [Larger forms](bench/large-full.rs) · [Other arguments](bench/edge-full.rs) · [Paths and headers](bench/additional-full.rs) · [Denial and upload](bench/coverage-full.rs)

| Workload | Before, µs | After, µs | Paired wall change | Faster pairs | CPU change |
|---|---:|---:|---:|---:|---:|
| [Form with 128 short fields](bench/limits/receipt.json) | 294.3 | 301.4 | +2.3% | 1/6 | +2.4% |
| [Form with 129 short fields](bench/limits/receipt.json) | 298.6 | 302.4 | +1.9% | 1/6 | +1.7% |
| [Form with 65 fields of 64 bytes (name + value)](bench/limits/receipt.json) | 472.7 | 474.2 | -0.3% | 4/6 | -0.5% |
| [Form with 257 distinct fields](bench/large/receipt.json) | 580.4 | 532.9 | -7.1% | 5/6 | -7.2% |
| [Form with 384 values under one case-folded key](bench/large/receipt.json) | 822.2 | 775.6 | -5.8% | 5/6 | -5.5% |
| [Form with 257 fields and a final UTF-8 value](bench/large/receipt.json) | 970.2 | 949.5 | -1.7% | 6/6 | -1.7% |
| [GET with a 65-byte argument](bench/varied/receipt.json) | 72.4 | 74.7 | +1.8% | 2/6 | +0.7% |
| [Form with 33 fields](bench/varied/receipt.json) | 148.4 | 142.1 | -4.1% | 5/6 | -4.1% |
| [JSON containing a UTF-8 value, space and slash](bench/varied/receipt.json) | 128.8 | 122.5 | -0.3% | 3/6 | -0.2% |
| [GET with a 110-byte decoded path](bench/additional/receipt.json) | 50.5 | 49.0 | -3.1% | 6/6 | -2.8% |
| [Form with a User-Agent over 64 bytes](bench/additional/receipt.json) | 60.7 | 59.5 | -1.7% | 5/6 | -2.0% |
| [JSON sent to a UTF-8 path](bench/additional/receipt.json) | 72.1 | 70.9 | -1.5% | 6/6 | -1.3% |
| [Denied PATCH](bench/coverage/receipt.json) | 35.9 | 36.6 | -0.1% | 3/6 | -0.2% |
| [GET with 33 additional headers](bench/coverage/receipt.json) | 89.0 | 89.8 | -0.2% | 4/6 | +0.0% |
| [Multipart POST with a text file](bench/coverage/receipt.json) | 60.0 | 60.8 | -0.8% | 3/6 | -0.9% |

The [resident worker](bench/resident.rs) wraps the same fixtures and measures elapsed and thread CPU time per batch. [Fixture and binary hashes](fixture-sources.json)

Eight additional interleaved pairs measured +0.7%, +0.3%, -0.4% for the 128-field, 129-field and 65-long-field forms. [Repeat timings](bench/limits-repeat/receipt.json)

## Large inputs with one indexed rule

Each custom request contained 8,192 fields. The first three cases use a phase-1 rule that looks up the named query parameter after parsing. The other eight use the same phase-2 rule for a query or a URL-encoded body. For the POST fixtures the parsing interval includes phase-2 evaluation. Complete request times include destruction. Paired blocks alternate revisions on CPU 12 and verify identical matches, captures and interventions. [Three lookup cases](sparse-phase/final/receipt.json) · [Eight encoding cases](sparse-phase/final-mixed/receipt.json) · [Lookup fixture](sparse-phase/sparse.rs) · [Encoding fixture](sparse-phase/mixed.rs)

| Workload | Parsing before → after, µs | Complete request before → after, µs | Paired request change | Faster pairs |
|---|---:|---:|---:|---:|
| GET, last field matches | 2,456 → 2,187 | 2,603 → 2,327 | -10.9% | 11/16 |
| GET, last field misses | 2,441 → 2,350 | 2,606 → 2,499 | -7.1% | 12/16 |
| GET, key absent | 2,475 → 2,208 | 2,628 → 2,367 | -11.5% | 13/16 |
| GET, plain | 1,779 → 1,447 | 1,827 → 1,488 | -20.9% | 14/16 |
| POST, plain | 1,779 → 1,407 | 1,828 → 1,445 | -20.8% | 15/16 |
| GET, one early escape | 1,804 → 1,365 | 1,849 → 1,404 | -22.3% | 15/16 |
| POST, one early escape | 1,802 → 1,392 | 1,852 → 1,432 | -21.6% | 15/16 |
| GET, one late escape | 1,826 → 1,406 | 1,872 → 1,438 | -19.4% | 15/16 |
| POST, one late escape | 1,807 → 1,392 | 1,856 → 1,438 | -22.3% | 16/16 |
| GET, every value escaped | 2,198 → 2,284 | 2,268 → 2,319 | +4.0% | 6/16 |
| POST, every value escaped | 2,190 → 2,275 | 2,238 → 2,314 | +5.9% | 4/16 |

The same single-rule lookup was also compared directly with `b2f41fe9`, the revision before the previous round’s 8,192-field regression. Complete requests improved by 16.4% (hit), 16.0% (miss) and 12.8% (absent). Median activity on the sibling CPU thread was 96% in this comparison. [Direct comparison](sparse-phase/pre-regression/receipt.json) · [Block means](sparse-phase/pre-regression/raw.json)

A repeat on the same CPU used 24 pairs with median activity on the sibling thread at 25%, compared with 100% for the eight encoding cases above. Plain and singly escaped requests took 14.4–16.4% less time. With every value escaped, the paired changes were -2.1% for GET and +1.2% for POST. In the busier run those two changes were +4.0% and +5.9%. [Repeat timings](sparse-phase/repeat-mixed/receipt.json) · [Block means](sparse-phase/repeat-mixed/raw.json)

The three sparse lookups were also repeated with less CPU contention. Against the last checkpoint, complete hit, miss and absent-key requests improved by 9.9%, 12.2% and 11.8%, with median sibling activity at 13%. [Paired results](sparse-phase/repeat-sparse/receipt.json) Against the pre-regression revision, complete hit, miss and absent-key requests improved by 8.0%, 10.7% and 9.4%, with median sibling activity at 16%. [Paired results](sparse-phase/repeat-pre-regression/receipt.json)

## Mixed traffic

The historical 706-rule configuration ran 24 mixed fixtures and 2,400 requests per process. Six counterbalanced pairs were followed by 12 pairs with a shifted starting fixture. The table shows medians of the 18 process quantiles and the median paired p99 change. [First six pairs](bench/mixed-final/receipt.json) · [Remaining twelve](bench/mixed-repeat/receipt.json)

| Detector | p50 before → after, µs | p99 before → after, µs | Paired p99 change | Faster p99 pairs |
|---|---:|---:|---:|---:|
| Rust | 120.1 → 117.3 | 248.3 → 236.3 | +0.2% | 9/18 |
| Optional C | 110.3 → 110.8 | 216.6 → 224.0 | +4.2% | 9/18 |

A further twelve counterbalanced pairs used the same executables. Paired p99 changes were -3.2% (7/12 faster) for Rust and -1.0% (8/12 faster) for optional C. Each point includes host scheduling as well as inspection time. [Confirmation](bench/mixed-confirmation/receipt.json) · [CPU activity](bench/mixed-confirmation-load.json)

## Memory and ruleset loading

The compiled CRS ruleset retained 31,539,765 → 31,539,765 live allocator bytes before its first request (+0 bytes). Fresh ruleset loading took 330.4 → 321.2 ms across twelve process pairs (-2.8% paired). [Ruleset heap](ruleset-heap-20db5d8b/receipt.json) · [Load times](bench/load-results.json)

On x86-64 the inline transaction measured 2,520 → 2,520 bytes, the request-data member 1,608 → 1,608 bytes and the per-rule dispatch record 168 → 168 bytes. [Rust type layouts](rust-layouts/20db5d8b74fd/receipt.json)

Allocation counters cover request creation through drop. These rows use unread audit getters. The receipt also covers audit reads during and after inspection. [Request allocations](verification/allocations.json)

| Workload | Allocation calls before → after | Requested bytes before → after |
|---|---:|---:|
| GET | 116 → 116 | 23,445 → 23,445 |
| Form POST | 164 → 164 | 26,025 → 26,025 |
| Nested JSON POST | 190 → 190 | 25,683 → 25,683 |

## Rule behavior

Formatting and strict Clippy passed. The default build passed 705 all-target tests and the optional C build passed 707. Both preserved all 5,187 native stage outcomes, 22 blocking traces and 24 complete audit records. The external CRS suite matched Coraza case for case, including its 4,655 passes, 17 failures and one fixture error. The reference detector corpus passed. [Verification](verification/summary.json)

Independent comparisons checked 21,239,508 regex/input pairs, 3,932,762 phrase/capture cases and 488,400 width decisions after request data changed. All 336 last-field matches survived. Two detector builds also compared 8,284 opaque or folded TX keys across 26 selectors. A separate corpus compared 1,262,625 TX selection decisions with an independent regex scan. The validator-aware collection check covered 7,563,544 transformed stages on the full CRS and 123,000 on its controls. [Regex](integrated-operators/20db5d8b74fd/receipt.json) · [Phrases](phase-phrase-differential/20db5d8b74fd/receipt.json) · [Collections](collection-boundary/20db5d8b74fd/receipt.json) · [TX selectors](tx-prefix-differential/20db5d8b.json) · [Independent TX decisions](tx-selector-differential/20db5d8b74fd/receipt.json)

Four workers sharing one ruleset produced the same ordered output as the baseline across five phases and two audit-read schedules. Separate comparisons checked form boundaries, engine-mode changes, early and late audit reads, and 1,680 dynamic `@within` cases. [Concurrent execution](final-engine-equivalence/receipt.json) · [Form boundaries](final-engine-equivalence/bound-fields-receipt.json) · [Engine modes](final-engine-equivalence/control-off-receipt.json) · [Audit reads](verification/audit-reads.json) · [Within operands](within-differential/20db5d8b.json) · [Within keys](within-key-differential/20db5d8b.json)

A public API comparison sent 6,192 generated inputs through both query and form POST parsing. The revisions produced byte-identical ordered names, canonical keys and values for all 12,384 parses, including invalid UTF-8 and escape sequences around the block boundary. A separate check verified that 32 transaction hash seeds remained independent after applying defaults. [Parser comparison](form-differential/receipt.json) · [Input generator](form-differential/fields.rs) · [TX hash checks](tx-hash-isolation/receipt.json)

A second generator compared the ordered collections from 256 additional query and form inputs, varying field length and encoding independently. [Fixture](sparse-phase/form-observables.rs) · [Results](sparse-phase/form-observables.json)

## Reproduce

Check out each benchmark revision, `181fbca01bf3142fc006fba61b4241165c2cd00b` and `20db5d8b74fd3ecc926f9375b734fb30e35e43e1`. Copy the [measurement lockfile](bench/Cargo.lock) to its root as `Cargo.lock`. Set `CRS_BENCH_DIR` to the absolute path of a clean OWASP CRS checkout at `aabf675fcfc5e489b424b844e6c9f1b39802df69`. Measurements used rustc 1.96.1 on x86-64 Linux. Alternate the order of the two revisions across eight pairs.

```sh
cargo bench --locked --bench modsec_bench -- full_crs --warm-up-time 0.3 --measurement-time 1 --sample-size 24 --nresamples 3000 --noplot
```

To exercise one of the supplementary fixtures with Criterion, copy its linked Rust file over `benches/modsec_bench/full_crs.rs` in each benchmark checkout and rerun the same command. The supplementary timing tables above used interleaved resident workers.

To reproduce the 8,192-field workloads, set `FIXTURE` to the absolute path of the [sparse lookup](sparse-phase/sparse.rs) or [mixed encoding](sparse-phase/mixed.rs) fixture. Run these commands in each benchmark checkout using its default Cargo target directory. The worker prints average nanoseconds per stage for 32 fresh requests per case after warmup. Confirm the two check outputs agree before comparing timings.

```sh
cargo build --locked --release --lib
rustc --edition=2021 -O "$FIXTURE" --extern zentinel_modsec=target/release/libzentinel_modsec.rlib -L dependency=target/release/deps -o target/release/form-timings
target/release/form-timings check
target/release/form-timings measure 32
```
