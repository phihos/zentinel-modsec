# Short argument and phrase matching on OWASP CRS 4.25.0

Engine `41e047f` follows fork checkpoint `e7cd1d3`. Four commits bound request-line caching, add minimum lengths to phrase searches, summarize short argument collections for regex rules, and apply the same argument checks to phrase rules. The benchmark revisions `87771dce` and `25f1d65f` have identical benchmark sources and match their respective engine sources and tests. [Source comparison](source-binding.json)

## Full-CRS request inspection

The benchmark from upstream PR #69 ran a clean CRS 4.25.0 checkout with 698 rules and blocking enabled. It verified the expected allow and deny decisions before timing request creation, headers, body, logging and drop. Eight pairs of Criterion processes alternated order on CPU 14 of an AMD Ryzen 7 5700X3D. Each process took 24 samples per workload. Before and after are medians of process means. Paired change is the median percentage difference within each pair. A second run alternated warmed workers every 96 transactions and measured both wall and thread CPU time. [Criterion](bench/criterion/receipt.json) · [Interleaved workers](bench/interleaved/receipt.json) · [Raw samples](samples.zip)

| Workload | Before, µs | After, µs | Paired change | Faster pairs | Interleaved wall change | CPU time change |
|---|---:|---:|---:|---:|---:|---:|
| GET | 63.4 | 52.2 | -18.5% | 8/8 | -16.5% | -16.6% |
| Form POST | 74.4 | 64.4 | -17.2% | 8/8 | -17.7% | -17.8% |
| Nested JSON POST | 90.6 | 75.4 | -16.0% | 8/8 | -15.0% | -14.9% |

## Larger and mixed requests

The phase summary examines up to 32 GET and POST argument members combined and classifies names and values separately. A field longer than 64 bytes makes its group ineligible. Unknown transformations, negated operators and counts use ordinary evaluation. These additional allowed requests use the full 698-rule configuration and the same inspection routine. Six paired runs alternated workers every 32 requests. [Workload source](bench/edge-full.rs) · [Measurements](bench/varied/receipt.json)

| Workload | Before, µs | After, µs | Paired change | Faster pairs |
|---|---:|---:|---:|---:|
| GET with a 65-byte value | 75.5 | 72.0 | -4.8% | 6/6 |
| Form with 33 fields | 250.7 | 227.0 | -9.3% | 6/6 |
| Nested JSON with a UTF-8 value, space and slash | 123.8 | 118.3 | -4.1% | 6/6 |

The historical 706-rule configuration ran 24 mixed fixtures, with 2,400 timed requests per process and six counterbalanced pairs per detector. [Mixed request timings](bench/mixed-final/receipt.json)

| Detector | p50 before → after, µs | Faster pairs | p99 before → after, µs | Faster pairs |
|---|---:|---:|---:|---:|
| Rust | 145.2 → 119.2 | 6/6 | 177.7 → 152.6 | 6/6 |
| Optional C | 139.5 → 111.2 | 6/6 | 170.2 → 151.0 | 6/6 |

Fresh ruleset loading measured 275.6 → 266.4 ms across twelve process pairs (-3.2% paired). [Cold-load samples](bench/load-results.json)

## Request allocation and correctness

Rules reading REQUEST_LINE can reuse the exact assembled bytes until the URI is replaced or the transaction ends. A cached copy can retain up to 4 KiB per transaction that reads it. Longer lines remain fully inspectable and are released after each lookup. The table counts cumulative allocator requests including reallocations on the original three benchmark workloads with audit getters unread. [Allocation results including early and late audit reads](verification/allocations.json)

| Workload | Allocation calls before → after | Bytes allocated before → after |
|---|---:|---:|
| GET | 158 → 136 | 27,070 → 26,644 |
| Form POST | 219 → 197 | 30,590 → 30,290 |
| Nested JSON POST | 245 → 223 | 30,182 → 29,882 |

Formatting, strict Clippy and all-target tests passed (690 on Rust and 692 with the optional C detector). Both retained all 5,187 native stage outcomes, 22 blocking traces and 24 complete audit records. External CRS outcomes matched Coraza case for case across 4,655 passes, 17 failures and one fixture error. The upstream libinjection corpus also passed. All 144 early and late audit-read cases matched the previous engine. [Full verification](verification/summary.json) · [Audit read comparison](verification/audit-prefix.json)

The regex comparisons covered 20,044,080 expression/input pairs against the original matcher. The phrase checks compared decisions, matched bytes and ordered captures against Aho–Corasick on 3,710,930 cases. Additional checks compared transformation stages and collection-level exclusions. Four workers sharing one ruleset matched serial execution and the previous engine across all five phases, including calls that read audit data during the request. [Regex and transformations](integrated-operators/25f1d65f38b5/receipt.json) · [Phrase comparisons](phase-phrase-differential/25f1d65f38b5/receipt.json) · [Concurrent transaction comparison](final-engine-equivalence/receipt.json)
