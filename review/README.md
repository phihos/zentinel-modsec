# OWASP CRS fixes for zentinel-modsec 0.6.0

[Upstream issue #68](https://github.com/zentinelproxy/zentinel-modsec/issues/68) · [Grouped pull requests](series.md) · [Original snapshot](https://github.com/phihos/zentinel-modsec/tree/9fa45f6061ff305568a63b61714beb70bfef4c8b) · [Current fork head](https://github.com/phihos/zentinel-modsec/tree/fix/haptic-plugin-sync)

| Upstream PR | Scope |
|---|---|
| [#69](https://github.com/zentinelproxy/zentinel-modsec/pull/69) | Benchmark GET, form POST and nested JSON POST on OWASP CRS 4.25.0. Merged. |
| [#70](https://github.com/zentinelproxy/zentinel-modsec/pull/70) | Return forward slashes from Windows path normalization. Merged. |
| [#71](https://github.com/zentinelproxy/zentinel-modsec/pull/71) | Fold full-width ASCII in `urlDecodeUni`. Merged. |
| [#72](https://github.com/zentinelproxy/zentinel-modsec/pull/72) | Encode non-ASCII code points in `utf8toUnicode`. Merged. |
| [#73](https://github.com/zentinelproxy/zentinel-modsec/pull/73) | Accept quoted numeric rule IDs. Merged. |
| [#74](https://github.com/zentinelproxy/zentinel-modsec/pull/74) | Match IPv4-mapped addresses against masked networks. Merged. |
| [#75](https://github.com/zentinelproxy/zentinel-modsec/pull/75) | Borrow compiled phase rules during request evaluation. Merged. |
| [#76](https://github.com/zentinelproxy/zentinel-modsec/pull/76) | Resolve includes as given, then beside the declaring file, and roll back the whole append on error. Merged. |
| [#77](https://github.com/zentinelproxy/zentinel-modsec/pull/77) | Apply `SecRuleRemoveByTag` and `SecRuleRemoveByMsg` to the whole ruleset. Merged. |
| [#78](https://github.com/zentinelproxy/zentinel-modsec/pull/78) | Preserve literal TX assignments and skip `setvar` into unimplemented collections with a warning. Merged. |
| [#79](https://github.com/zentinelproxy/zentinel-modsec/pull/79) | Keep loading past form feeds, Unicode spaces and line terminators. Merged. |
| [#80](https://github.com/zentinelproxy/zentinel-modsec/pull/80) | Convert empty and non-numeric operands to zero in numeric operators. Merged. |
| [#81](https://github.com/zentinelproxy/zentinel-modsec/pull/81) | Keep TX score variables set by rules when a phase ends. Merged. |
| [#82](https://github.com/zentinelproxy/zentinel-modsec/pull/82) | Saturate `setvar` arithmetic at the signed 64-bit boundary. Merged. |
| [#87](https://github.com/zentinelproxy/zentinel-modsec/pull/87) | Leave numeric operators with a bare macro name unable to match. Merged. |
| [#91](https://github.com/zentinelproxy/zentinel-modsec/pull/91) | Answer non-matching `@rx` values without building capture slots. Merged. |
| [#92](https://github.com/zentinelproxy/zentinel-modsec/pull/92) | Collect rule metadata only when a rule intervenes. Merged. |
| [#93](https://github.com/zentinelproxy/zentinel-modsec/pull/93) | Expand operand macros without a regex and flag macro operands at load. Merged. |
| [#94](https://github.com/zentinelproxy/zentinel-modsec/pull/94) | Resolve rule targets without copying names and values. Merged. |
| [#97](https://github.com/zentinelproxy/zentinel-modsec/pull/97) | Resume after a `skipAfter` marker that directly follows the rule. Merged. |
| [#98](https://github.com/zentinelproxy/zentinel-modsec/pull/98) | Read collections in place when resolving targets and expanding macros. Merged. |
| [#100](https://github.com/zentinelproxy/zentinel-modsec/pull/100) | Prepare rule tags and `skipAfter` positions at load. Merged. |
| [#103](https://github.com/zentinelproxy/zentinel-modsec/pull/103) | Prepare what a rule's match does at load. |

The fix PRs use the benchmark merged in #69 for measurement. The [grouped series](series.md) shows which changes are filed and how the remaining work fits together. It identifies overlap with #65 and #67. The Windows and Unicode fixes together recover 47 cases on the upstream CI checkout.

## Request timing

The experiments below each used four counterbalanced process pairs on a shared host, pinned to one logical CPU. Each process took 24 Criterion samples per workload. Entries are medians of process means, in microseconds. See the [benchmark instructions](https://github.com/zentinelproxy/zentinel-modsec/pull/69/files) for the pinned rules and fixtures.

| Change under test | GET before → after | Form POST before → after | JSON POST before → after |
|---|---:|---:|---:|
| #75 alone | 783.2 → 244.9 | 890.6 → 322.0 | 927.4 → 355.3 |
| Entire fork vs upstream 0.6.0 | 822.2 → 76.3 | 932.9 → 92.5 | 934.0 → 114.0 |
| Current fork head vs upstream main | 831.9 → 39.5 | 943.5 → 49.4 | 985.6 → 57.7 |

The first row measures the phase-rule borrowing patch. The second row includes every engine and detector change on the fork at the original snapshot. The third row repeats that comparison with the later fork work against upstream main at #69. Each archive contains the Criterion samples, estimates and dependency lockfiles. The accompanying JSON records source revisions, binary hashes and individual run means.

- Phase-rule borrowing. [Run summary](measurements/phase-borrow.json) · [Raw samples](measurements/phase-borrow-samples.tar.gz) · [Benchmarked source](https://github.com/phihos/zentinel-modsec/tree/measure/borrow-phase-rules)
- Whole snapshot. [Run summary](measurements/snapshot.json) · [Raw samples](measurements/snapshot-samples.tar.gz) · [Benchmarked source](https://github.com/phihos/zentinel-modsec/tree/measure/full-crs-snapshot)
- Current fork head. [Run summary](measurements/plugin-sync.json) · [Raw samples](measurements/plugin-sync-samples.tar.gz) · [Driver](measurements/plugin-sync-pairs.py) · [Benchmarked source](https://github.com/phihos/zentinel-modsec/tree/measure/haptic-plugin-sync)

PRs #69–76 passed formatting, strict Clippy, all-target tests, doctests and release-mode conformance on the CI-pinned CRS checkout. [Results for #69–75](local-ci.json) · [Results for #76](config-loading-ci.json) These results predate the review changes to #76. #76–82 passed the same jobs in upstream CI.
