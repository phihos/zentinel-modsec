# Further request latency reductions on OWASP CRS 4.25.0

Engine commits `d410f28` and `2725d4b` on `spike/crs-parity` follow the regex-width checkpoint at `a213869`. The benchmark was identical on both builds. Source, tests, manifests and vendor files matched the respective local engine revisions. [Measured revisions](source-binding.json)

## Warm request inspection

The benchmark from upstream PR #69 loaded 698 rules with blocking enabled. It preflighted three allowed requests, JSON body processing and one blocked request. The timer measures transaction creation through request headers, body inspection, logging and drop. Eight pairs of Criterion processes alternated order on CPU 14 of an AMD Ryzen 7 5700X3D. Each process took 24 samples per workload. Before and after are medians of process means. The change column is the median of the eight within-pair percentage differences. [Raw Criterion samples](samples.zip) · [Paired results and binary hashes](bench/final-criterion/receipt.json)

| Workload | Before, µs | After, µs | Paired change | Faster pairs |
|---|---:|---:|---:|---:|
| GET with query parameters | 76.9 | 71.8 | -11.2% | 6/8 |
| Form POST | 92.9 | 84.8 | -9.8% | 8/8 |
| Nested JSON POST | 122.3 | 106.9 | -15.5% | 8/8 |

Other builds and tests were active on the host. A second run used the same benchmark request function and switched between warmed workers every 96 requests. Thread CPU time excludes periods when the measuring thread was descheduled. This run also used eight process pairs. [Wall and thread CPU samples](bench/final-interleaved/receipt.json)

| Workload | Paired wall time change | Faster pairs | Paired CPU time change | Faster pairs |
|---|---:|---:|---:|---:|
| GET with query parameters | -9.4% | 8/8 | -9.4% | 8/8 |
| Form POST | -9.8% | 8/8 | -9.8% | 8/8 |
| Nested JSON POST | -16.8% | 8/8 | -16.6% | 8/8 |

## Mixed traffic and cold load

The historical 706-rule configuration ran 24 mixed fixtures, with 2,400 timed requests per process and six counterbalanced process pairs per detector. Each figure is the median of the six per-process percentiles. [Mixed request samples and pair results](bench/mixed-final/receipt.json)

| Detector | p50 before → after, µs | Faster pairs | p99 before → after, µs | Faster pairs |
|---|---:|---:|---:|---:|
| Rust | 163.2 → 155.2 | 6/6 | 203.6 → 186.5 | 5/6 |
| Optional C | 158.9 → 151.0 | 6/6 | 245.8 → 231.7 | 4/6 |

Fresh ruleset loading on the 698-rule benchmark measured 279.4 → 277.5 ms across 12 fresh-process pairs (-0.4% paired). The timer includes reading and compiling the configuration. [Load samples](bench/load-results.json)

## Changes and correctness

- The first commit prepares a leading sequence of deterministic TX assignments once when the ruleset loads. For the full CRS this covers 25 rules and 44 assignments. Transactions with preseeded TX values or optional diagnostic recording use the ordinary evaluator. Four concurrent workers and serial controls produced identical ordered TX contents, rule IDs, match data, captures and interventions across five phases, with both early and late audit reads. [Plan counts](tx-default-equivalence/zentinel-tx-default-profile2.log) · [Final equivalence results](tx-final-equivalence/receipt.json)
- The second commit recognizes ASCII path separators when calculating minimum match widths and recognizes regexes that require a particular literal byte. The path-width change alone avoided a net 15 searches for GET, 29 for form and 176 for JSON. Across all 291 static CRS regexes and 68,880 inputs, the final engine agreed with the original regex builder on decisions, matched portions and subgroups in all 20,044,080 comparisons. [Search counts](differential/token-counts.log) · [Final regex differential](differential/final-24a6186/receipt.json)
- Formatting, strict Clippy and all-target tests passed on both backends (681 default Rust and 683 with the C detector). Both matched the pinned native stage outcomes, 22 blocking traces and 24 complete audit records. External CRS 4.25.0 case IDs matched Coraza for 4,655 passes, 17 failures and one client error. The upstream libinjection corpus also passed. [Verification summary](../perf-post-grouped/verification/24a6186c2207/summary.json)
- The two parsing experiments remain separate. Borrowing JSON strings and folding short header names into inline storage reduced allocations, but adding them to the selected runtime raised paired form POST latency by 3.0% and slowed five of six pairs. [Incremental comparison](bench/parsing-measure/receipt.json)
