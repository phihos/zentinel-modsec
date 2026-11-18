# Request inspection and audit allocation on OWASP CRS 4.25.0

Engine commits `32f40b6`, `7c1cf5b` and `9762969` follow checkpoint `573f9bc`. The retained changes defer fixed phase-one audit records until a caller reads them, recognize built-in transformations that preserve short inputs, and use a tighter regex minimum width for alphanumeric input. Both builds used the same benchmark source and Cargo lockfile at revisions `24a6186c` and `87771dce`. The engine and tests in each benchmark build match the corresponding implementation revision. [Source comparison](source-binding.json)

## Warm inspection

The benchmark from upstream PR #69 loads 698 rules with blocking enabled and checks three allowed requests and a denial before measuring. Each transaction includes request headers, body inspection, logging and drop. Eight pairs of Criterion processes alternated order on CPU 14 of an AMD Ryzen 7 5700X3D, with 24 samples per workload per process. Before and after are medians of the eight process means. Paired changes are medians of the differences in percent within each pair. A second run interleaved the same warmed requests every 96 transactions, recording wall and thread CPU time. [Criterion results](bench/criterion/receipt.json) · [Interleaved results](bench/interleaved/receipt.json) · [Raw request timing samples](samples.zip)

| Workload | Before, µs | After, µs | Paired change | Faster pairs | Interleaved wall change | Thread CPU change |
|---|---:|---:|---:|---:|---:|---:|
| GET | 61.9 | 58.7 | -4.4% | 7/8 | -3.9% | -3.8% |
| Form POST | 77.3 | 72.2 | -4.8% | 8/8 | -3.2% | -3.1% |
| Nested JSON POST | 93.1 | 87.4 | -8.8% | 7/8 | -7.2% | -7.2% |

## Mixed traffic and cold loading

The 706-rule mixed-traffic configuration ran six counterbalanced pairs per detector, with 24 fixtures and 2,400 timed requests per process. The table shows the median of the per-process percentiles. [Mixed timings](bench/mixed-final/receipt.json)

| Detector | p50 before → after, µs | Faster pairs | p99 before → after, µs | Faster pairs |
|---|---:|---:|---:|---:|
| Rust | 154.7 → 145.5 | 6/6 | 191.4 → 181.9 | 6/6 |
| Optional C | 148.1 → 139.3 | 6/6 | 182.6 → 173.4 | 5/6 |

Reading and compiling all 698 rules in twelve fresh-process pairs took 272.2 → 274.5 ms (+0.8% paired). [Cold-load samples](bench/load-results.json)

## Audit allocation

The allocator probe uses the benchmark requests. It counts cumulative bytes requested per transaction, including reallocations. Each reading mode calls both audit getters at the indicated phases. Early reads reserve space for later matches and can retain spare capacity until drop. [Allocation counts and bytes for every reading mode](verification/allocations.json)

| Audit reads | GET bytes, before → after | Form POST bytes, before → after | JSON POST bytes, before → after |
|---|---:|---:|---:|
| None | 32,651 → 27,070 | 34,123 → 30,590 | 36,405 → 30,182 |
| After phase 1 | 51,536 → 38,416 | 51,938 → 38,818 | 55,352 → 41,590 |
| After logging | 48,296 → 42,888 | 49,530 → 46,170 | 52,304 → 46,254 |
| After phase 1 and logging | 51,536 → 38,416 | 51,938 → 38,818 | 55,352 → 41,590 |

When audits were read only after logging, GET used one extra allocation and form POST two extra allocations, while allocating 5,408 and 3,360 fewer bytes per request respectively. All 144 early and late audit cases produced identical output. [Audit comparison](verification/audit-prefix.json)

## Correctness

On both detector backends the external CRS case IDs agreed with Coraza across 4,655 passes, 17 failures and one client fixture error. The two backends retained all 5,187 native stage outcomes, 22 ordered blocking traces and 24 complete audit records. Formatting, strict Clippy, all-target tests and the upstream libinjection corpus passed. [Repository and corpus checks](verification/summary.json)

Four concurrent workers sharing a ruleset reproduced serial execution and the previous engine for ordered TX values, captures, matches and interventions across all five phases. The comparison included callers reading audit data throughout a request and callers waiting until logging. [Transaction equivalence](engine-equivalence/receipt.json)

The regex comparison covered 291 distinct CRS expressions on 68,880 inputs. All 20,044,080 decisions, including matched spans and subgroups, agreed with the reference matcher. The transformation comparison covered 3,121,146 output and ownership checks, 3,460,642 ordered stage visits and 464,605 early rejections. [Differential checks and source hashes](operator-differentials/87771dce375e/receipt.json)
