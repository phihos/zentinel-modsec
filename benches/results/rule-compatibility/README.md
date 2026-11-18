# Three Coraza 3.8.1 compatibility fixes

Runtime `902b2db` matches Coraza's URL encoder on all 256 input bytes. The same missing TX or header member expands to the same original name in operators, messages and log data, including the optimized `@within` path. `ctl:forceResponseBodyVariable` can select responses outside the configured MIME list when response inspection is enabled. Ten Coraza transactions covered forced inspection, writes before headers, toggle order, and disabled access. [URL encoding](url-encode.json) · [Macro output](macros.txt) · [Response control](response.txt)

Both detector builds matched the Coraza case sets on CRS 4.25.0, all 22 Coraza blocking traces and the previous Rust results on all 24 audit fixtures. The full Rust test run used `6f62c80`, which updated a unit test fixture. [Qualification](qualification.json) · [Test totals](tests.json)

## Full CRS timing

Each run compared eight interleaved pairs using the ordinary GET, form and JSON requests from the full 698-rule benchmark, default Rust detector. The table reports the median within-pair change from `19cc499` to `902b2db`. Positive values indicate more time per request. The host was shared with other workloads. [Initial measurements](timings/initial/summary.json) · [Repeat measurements](timings/repeat/summary.json)

| Request | Thread CPU, first | Thread CPU, repeat | Wall, first | Wall, repeat |
|---|---:|---:|---:|---:|
| GET | +0.9% | +3.7% | +0.8% | +4.2% |
| Form POST | +8.9% | +2.6% | +5.1% | +3.6% |
| JSON POST | -0.8% | +1.3% | -1.5% | +9.8% |
