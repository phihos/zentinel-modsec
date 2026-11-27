# Profile-guided release on upstream main

Compared ordinary and profile-guided releases of upstream 0.13.3 on 698 CRS 4.25.0 rules. Entries show median process means in microseconds per request and the median within-pair latency reduction. Each build ran 2,200 transactions per fixture after warmup, with eight alternating process pairs on each of two physical cores of a Ryzen 7 5700X3D. Training used different routes and bodies. These are clean engine transaction timings.

| Matched data | GET | Form POST | JSON POST |
|---|---:|---:|---:|
| Unread | 59.8 → 49.4 (17.3%) | 71.8 → 58.9 (18.1%) | 81.0 → 67.4 (17.1%) |
| Read at end | 63.4 → 52.8 (16.7%) | 75.7 → 62.8 (17.5%) | 84.9 → 71.0 (16.2%) |

All four upstream CI checks passed. The locally profiled release passed the stock blocking checks and matched main at 4,979 of 5,184 runnable CRS cases, with 41 skipped. All 10,368 after-header and after-body snapshots of matched IDs, data, messages and interventions agreed byte for byte with main.

Rust 1.95.0, LLVM 21.1.8, x86_64 Linux, logical CPUs 12 and 14. Both executables were built from PR head `ef81e38` based on `a3a5f2c`, using the same dependency lockfile. Each sample records the ordinary build under `base` and the profiled build under `fast`. [Paired samples](pairs.json) · [PR #150](https://github.com/zentinelproxy/zentinel-modsec/pull/150)
