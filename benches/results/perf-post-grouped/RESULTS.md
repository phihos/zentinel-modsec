# Regex match width on full OWASP CRS 4.25.0

The default Rust engine inspected GET and form requests about 11–12% faster. A fresh ruleset took about 8 ms longer to compile. The engine compiles the regex and computes its minimum match widths from a single parsed expression. If a short ASCII token cannot contain a match, the evaluator can return the regex result without searching. Eligible matches and captures still use the underlying regex engine.

The previous engine was `9fa45f6`. The change is `a213869` on `spike/crs-parity`. The measured revisions `055c8f48` and `ce20b3ad` add the identical benchmark from upstream PR #69 and omit the local handoff. Cargo manifests, runtime sources and tests were checked against the corresponding implementation revisions. The two newly direct dependencies were already present at the same versions in the previous dependency graph.

## Request inspection

The benchmark loaded all 698 rules on the CRS 4.25.0 release with blocking enabled and preflighted allowed requests and a denial. Eight process pairs alternated order on logical CPU 14. Each Criterion process took 24 samples per workload. Before and after are medians of the eight process means. Percentages are medians of the within-pair changes.

| Workload | Previous µs | New µs | Paired reduction | Faster pairs |
|---|---:|---:|---:|---:|
| GET with query parameters | 73.9 | 64.1 | 12.4% | 8/8 |
| Form POST | 87.6 | 77.7 | 11.2% | 8/8 |
| Nested JSON POST | 109.7 | 104.9 | 3.3% | 8/8 |

A separate run interleaved the same warmed workers every 96 requests. It measured reductions of 12.1% for GET, 10.6% for form and 0.9% for JSON. The JSON benefit varied with timing method. [Criterion process means and revisions](bench/single-parse-criterion/receipt.json) · [Criterion samples](samples.zip) · [Interleaved timings](bench/single-parse-resident/receipt.json)

## Varied traffic

The existing 24 mixed fixtures cover repeated headers, queries, encoded forms and nested JSON. Six counterbalanced process pairs each measured 2,400 requests per build after warmup on the 706-rule comparison configuration. All six pairs improved at both percentiles for each detector. [Per-pair results and worker hashes](bench/mixed-final/receipt.json)

| Detector | p50 before → after | p99 before → after |
|---|---:|---:|
| Rust | 177.2 → 161.5 µs | 218.9 → 204.7 µs |
| Optional C | 167.6 → 153.9 µs | 203.2 → 200.9 µs |

## Ruleset loading and correctness

Across twelve counterbalanced fresh-process pairs the median full-CRS load increased from 265.4 to 273.9 ms, a 3.0% paired increase. The timer includes reading and compiling the configuration. An earlier implementation parsed each regex twice and increased load time by 41.8%. [Final load samples](bench/load-results.json) · [Two-parse experiment](bench/double-parse-load-results.json)

An independent comparison against the previous byte regex builder exercised 291 distinct CRS regexes on 68,875 inputs each. It found zero differences in 20,042,625 comparisons covering decisions, matched spans and captures. Separate tests checked invalid syntax and compiled size errors. [Differential results](regex-width/single-parse-differential.log)

Both detectors retained the same case IDs as Coraza for 4,655 passes, 17 failures and one client fixture error. Both reproduced all 5,187 native stage outcomes, 22 blocking traces and 24 complete audit records. Formatting, strict Clippy, all-target tests and the upstream libinjection differential passed. [Verification and case counts](verification/ce20b3ad03dd/summary.json)
