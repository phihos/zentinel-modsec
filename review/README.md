# OWASP CRS fixes for zentinel-modsec 0.6.0

[Upstream issue #68](https://github.com/zentinelproxy/zentinel-modsec/issues/68) · [Complete review queue](series.md) · [Original snapshot](https://github.com/phihos/zentinel-modsec/tree/9fa45f6061ff305568a63b61714beb70bfef4c8b)

| Upstream PR | Scope |
|---|---|
| [#69](https://github.com/zentinelproxy/zentinel-modsec/pull/69) | Benchmark GET, form POST and nested JSON POST on OWASP CRS 4.25.0. |
| [#70](https://github.com/zentinelproxy/zentinel-modsec/pull/70) | Return forward slashes from Windows path normalization. |
| [#71](https://github.com/zentinelproxy/zentinel-modsec/pull/71) | Fold full-width ASCII in `urlDecodeUni`. |
| [#72](https://github.com/zentinelproxy/zentinel-modsec/pull/72) | Encode non-ASCII code points in `utf8toUnicode`. |
| [#73](https://github.com/zentinelproxy/zentinel-modsec/pull/73) | Accept quoted numeric rule IDs. |
| [#74](https://github.com/zentinelproxy/zentinel-modsec/pull/74) | Match IPv4-mapped addresses against masked networks. |
| [#75](https://github.com/zentinelproxy/zentinel-modsec/pull/75) | Borrow compiled phase rules during request evaluation. |

PRs #70–75 depend on #69 for measurement. Each has a one-change diff against upstream main. The full queue includes the corresponding source patches and marks overlaps with #65 and #67. Take the observed corpus count after each merge. The Windows and Unicode fixes together recover 47 cases on the upstream CI checkout.

## Request timing

The two experiments below each used four counterbalanced process pairs on a shared host, pinned to one logical CPU. Each process took 24 Criterion samples per workload. Entries are medians of process means, in microseconds. See the [benchmark instructions](https://github.com/zentinelproxy/zentinel-modsec/pull/69/files) for the pinned rules and fixtures.

| Change under test | GET before → after | Form POST before → after | JSON POST before → after |
|---|---:|---:|---:|
| #75 alone | 783.2 → 244.9 | 890.6 → 322.0 | 927.4 → 355.3 |
| Entire fork vs upstream 0.6.0 | 822.2 → 76.3 | 932.9 → 92.5 | 934.0 → 114.0 |

The first row measures the phase-rule borrowing patch. The second row includes every engine and detector change on the fork. Each archive contains the Criterion samples, estimates and dependency lockfiles. The accompanying JSON records source revisions, binary hashes and individual run means.

- Phase-rule borrowing. [Run summary](measurements/phase-borrow.json) · [Raw samples](measurements/phase-borrow-samples.tar.gz) · [Benchmarked source](https://github.com/phihos/zentinel-modsec/tree/measure/borrow-phase-rules)
- Whole snapshot. [Run summary](measurements/snapshot.json) · [Raw samples](measurements/snapshot-samples.tar.gz) · [Benchmarked source](https://github.com/phihos/zentinel-modsec/tree/measure/full-crs-snapshot)
