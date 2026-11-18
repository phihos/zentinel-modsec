# Rule and body compatibility with Coraza 3.8.1

The qualified engine is [19cc499](https://github.com/phihos/zentinel-modsec/commit/19cc49939494341eba3bcace2b92699f5b079706). Both the Rust and C detector builds matched every Coraza result on the external CRS 4.25.0 run, with 4,655 passes, 17 failures and one client fixture error. All 22 blocking traces matched Coraza. All 24 complete connector audit records matched the previous Rust build. A separate denied request checked the transaction ID, rule ID, message and log data against Coraza’s JSON audit writer. [Corpus comparisons](qualification.json) · [Checks and fixed-ID sampling](checks.json)

The Go reference cases exercise schema validation, overlapping response field names and processor errors. [Go program](coraza-json.go) · [Observed results](coraza-json.txt)

## Cost on ordinary requests

The benchmark in [upstream PR 69](https://github.com/zentinelproxy/zentinel-modsec/pull/69) loaded all 698 rules of OWASP CRS 4.25.0 with the default Rust detector. Each run used eight pairs of fresh, warmed processes and alternated revisions between batches. The baseline binary came from `20db5d8`, which has identical engine source to the preceding fork checkpoint `bfdde06`. The table gives the median within-pair change relative to that baseline. Positive values indicate greater cost.

| Request | Wall, first run | Wall, repeat | Thread CPU, first run | Thread CPU, repeat |
|---|---:|---:|---:|---:|
| GET | +1.7% | −7.4% | +2.1% | +0.6% |
| Form POST | +5.2% | +1.4% | +3.2% | +3.3% |
| JSON POST | +1.1% | −1.4% | +0.9% | +1.4% |

Both runs used CPU 14. Before the repeat, its physical core had the lowest measured load among the eligible cores and was still over 97% busy. Form POST showed the most consistent increase in CPU time across the two runs. [First run](timings/initial/summary.json) · [Repeat](timings/repeat/summary.json) · [CPU selection](timings/repeat/selection.json)
