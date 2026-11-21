# Grouped pull requests

The full OWASP CRS benchmark comes first. The results for upstream 0.6.0 and the complete fork are in [issue #68](https://github.com/zentinelproxy/zentinel-modsec/issues/68) and the [benchmark results](README.md#request-timing).

## Filed upstream

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
| [#103](https://github.com/zentinelproxy/zentinel-modsec/pull/103) | Prepare what a rule's match does at load. Merged. |

## Queued on the fork

Following review, the filed PRs keep ModSecurity v3 semantics where v3 and Coraza differ, and warn instead of failing the load for unsupported features. The groups below were built for Coraza 3.8.1 parity and will be adapted the same way when filed. #80–82 are the first extractions from these groups.

Since the snapshot, the fork added transaction-local body policy, JSON schema validation, a connector profile that selects Coraza behavior, and further request-path optimizations. That work is on [`fix/haptic-plugin-sync`](https://github.com/phihos/zentinel-modsec/compare/9fa45f6061ff305568a63b61714beb70bfef4c8b...fix/haptic-plugin-sync) and is not yet grouped.

The 146 implementation commits beyond #70–75 are covered by #76 and the 18 groups below. Each link shows the changes since the preceding group. As prerequisites merge upstream, each group can be filed against its merged base with the same focused diff. The starting point combines #69–75 and the configuration changes filed in [#76](https://github.com/zentinelproxy/zentinel-modsec/pull/76).

| Proposed change |
|---|
| [Match original bytes with Rust libinjection and an optional C reference](https://github.com/phihos/zentinel-modsec/compare/fdd01da5d2551892920a9bd29f926ecae89d2b76...07e2ae39628f221d5f673a0fdfb94cc71d1f3eb8) |
| [Normalize and transform original bytes across built-in stages](https://github.com/phihos/zentinel-modsec/compare/07e2ae39628f221d5f673a0fdfb94cc71d1f3eb8...eadc8d119de09ffe8b60b0f1c10ec4ad3fb8f3ce) |
| [Implement tag-target exclusions and validate rules at load time](https://github.com/phihos/zentinel-modsec/compare/eadc8d119de09ffe8b60b0f1c10ec4ad3fb8f3ce...1aec5bef994cfdbf1b0f21785536742c4f579e1a) |
| [Expose original HTTP bytes to variables and operator predicates](https://github.com/phihos/zentinel-modsec/compare/1aec5bef994cfdbf1b0f21785536742c4f579e1a...e5a71447683c2dfd8edb4cf709213dd1d28a550f) |
| [Expose XML nodes and preserve JSON scalar values](https://github.com/phihos/zentinel-modsec/compare/e5a71447683c2dfd8edb4cf709213dd1d28a550f...ee16ce519f4eabb6cc6133a99d7c603abbe113af) |
| [Respect body processor selection and actual response metadata](https://github.com/phihos/zentinel-modsec/compare/ee16ce519f4eabb6cc6133a99d7c603abbe113af...f7bf9bb6930f9afb6047c626697c0408b27cfcea) |
| [Evaluate changed byte stages, captures and macros in match order](https://github.com/phihos/zentinel-modsec/compare/f7bf9bb6930f9afb6047c626697c0408b27cfcea...64a60765fb3b0241d7a9692a8857be312ced6a40) |
| [Parse multipart names, headers and file values from original bytes](https://github.com/phihos/zentinel-modsec/compare/64a60765fb3b0241d7a9692a8857be312ced6a40...0546b6a39c702fd92dae6586a8c7d62cf5fe4725) |
| [Bound body acquisition and preserve callback order](https://github.com/phihos/zentinel-modsec/compare/0546b6a39c702fd92dae6586a8c7d62cf5fe4725...f92d54197c7535375ab762f6be604df81779d5ef) |
| [Preserve header spelling and request metadata across callbacks](https://github.com/phihos/zentinel-modsec/compare/f92d54197c7535375ab762f6be604df81779d5ef...6605f412bd579077c58e3d2970a1906ff45e447c) |
| [Apply ordered actions, scores and interventions at match time](https://github.com/phihos/zentinel-modsec/compare/6605f412bd579077c58e3d2970a1906ff45e447c...facd119b56fa567822520e86dafb3bb1ef7e8723) |
| [Index named collections and compile selector exclusions](https://github.com/phihos/zentinel-modsec/compare/facd119b56fa567822520e86dafb3bb1ef7e8723...3bda255d51734225242b6d5dd2adc133453d158c) |
| [Evaluate borrowed targets and honor disruptive rule flow](https://github.com/phihos/zentinel-modsec/compare/3bda255d51734225242b6d5dd2adc133453d158c...9a55b39860634673b02595bebb1c4da0b3a8c702) |
| [Validate native operators and compile rule-ID action updates](https://github.com/phihos/zentinel-modsec/compare/9a55b39860634673b02595bebb1c4da0b3a8c702...1454d70973572dabd68299fbe6393e52bf15a781) |
| [Compile phase dispatch and visit selected targets directly](https://github.com/phihos/zentinel-modsec/compare/1454d70973572dabd68299fbe6393e52bf15a781...e7b8263607c60259b29d90623c7968a9ef66e022) |
| [Publish matched bytes and IDs on demand](https://github.com/phihos/zentinel-modsec/compare/e7b8263607c60259b29d90623c7968a9ef66e022...aea0eab5d56d22ec23ffd935f0ce7ff32efcf0dd) |
| [Reuse live TX positions and prepared rule actions](https://github.com/phihos/zentinel-modsec/compare/aea0eab5d56d22ec23ffd935f0ce7ff32efcf0dd...d0afffbaa13548e69e9b16fdf881212eb58c7856) |
| [Gate both detectors on pinned native CRS outcomes](https://github.com/phihos/zentinel-modsec/compare/d0afffbaa13548e69e9b16fdf881212eb58c7856...055c8f4849c1b2bca47366e45af6226944dfb13e) |

The tag controls overlap with [#65](https://github.com/zentinelproxy/zentinel-modsec/pull/65). Forced body inspection and multipart upload sizes overlap with [#67](https://github.com/zentinelproxy/zentinel-modsec/pull/67). Those groups need reconciliation with the maintainer’s work before filing.

The detector group includes the [upstream C source import](https://github.com/phihos/zentinel-modsec/commit/dded2627934b9380e909d68ab5635a17d67b1557). The last group includes the [pinned per-stage fixture](https://github.com/phihos/zentinel-modsec/commit/eb096086a29803324b79ea28352d5dcbd9feec02). The Unicode mapping and XML entity table also have dedicated import commits. The [original commit index](commits.md) gives smaller diffs for individual implementation changes.

The last group has the same engine, detector and test files as the [benchmarked snapshot](https://github.com/phihos/zentinel-modsec/tree/9fa45f6061ff305568a63b61714beb70bfef4c8b). The review stack adds the benchmark from #69 and omits the local handoff document. [Exact group revisions](groups.json)

Formatting, strict Clippy, unit tests and the changed integration tests passed on all 19 groups. The release-mode native CRS suite and stock blocking check also passed on every group, with both detector builds from the group that introduces the optional C detector onward. The final fixture evaluated 5,187 stages and recorded 5,096 passing stages, with 76 additional stages skipped. [Results by group](grouped-checks.json)

The shared base passed 4,947 of 5,184 evaluated stages. Three stages temporarily failed after the byte transforms and recovered with the match-order changes. Five temporarily failed after the XML and JSON changes and recovered with body processor selection. Two cases that passed at the base fail on both detectors at the final head. Case 5 of rule 920640 covers HTTP framing in the native test client. Case 5 of rule 920430 covers an empty protocol version. The final fixture records both outcomes and evaluates three additional stages.
