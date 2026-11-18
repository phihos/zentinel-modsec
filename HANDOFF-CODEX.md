# Coraza parity handoff — 2026-11-18

## Current checkpoint

Engine `8aba31c` caches argument widths across phases, precomputes fixed rule
target masks and accelerates simple anchored TX key selectors. Compared with
`d872a35`, eight paired runs on the full 698-rule CRS 4.25.0 configuration
measured 5.4% lower GET latency, 5.1% lower form POST latency
and 5.2% lower nested JSON POST latency. A 129-field form fell from
701 to 296 µs and a 257-field form from
1,315 to 581 µs. On the separate mixed workload,
median process p99 moved from 148.8 to 150.6 µs with the Rust detector
and from 142.0 to 139.4 µs with the optional C detector.

Both backends preserved corpus outcomes, blocking decisions and audit data.
The 698-rule heap and request allocation counts held steady. The inline
transaction grew by 112 bytes on x86-64. A custom single-rule lookup across
an 8,192-field request retained its indexed lookup speed, while the complete
request including parsing took 2.4–2.6% longer. The
[benchmark report and raw samples](https://github.com/phihos/zentinel-modsec/blob/measure/full-crs-snapshot/benches/results/crs-round7/RESULTS.md)
cover all 18 full-CRS fixtures, both mixed-traffic detectors and the custom rule.

## Argument budget checkpoint at `93870ea`

Engine `93870ea` includes the rule-selection and allocation changes from
`ece387f` and replaces the 32-field cutoff with a 4 KiB argument scan budget.
GET and POST share the budget, with a minimum charge of 32 bytes per member.
Past the limit the engine evaluates the whole collection normally.

Compared directly with the round's starting checkpoint `6f35d92`, the full
698-rule OWASP CRS 4.25.0 benchmark measured 4.6% lower GET latency, 4.0% lower
form POST latency and 9.4% lower nested JSON POST latency across eight pairs.
Forms with 33 and 128 short fields improved by 39.4% and 53.7%. Forms beyond
the budget measured 7.0% slower for 129 short fields and 1.6% slower for
65 fields of 64 bytes each. Both detector backends retained the pinned corpus
outcomes, blocking traces and complete audit records. Checks around the limits
also retained all last-field matches. The [report and raw samples](https://github.com/phihos/zentinel-modsec/blob/measure/full-crs-snapshot/benches/results/crs-round6-budget/RESULTS.md)
include boundary workloads, mixed-traffic p99, allocator totals and cold-load timings.

## Rule target selection and TX search checkpoint at `ece387f`

Engine `ece387f` follows `6f35d92`. On the full 698-rule OWASP CRS 4.25.0
benchmark, 16 paired runs measured 6.1% lower GET latency, 4.9% lower form
POST latency and 9.7% lower nested JSON POST latency. Rust p99 on mixed traffic
fell from 156.1 to 150.3 µs and optional C p99 from 154.3 to 142.7 µs.
The 33-field form regressed 2.6%. The compiled ruleset retained 22,808 extra
bytes. Per-request allocation calls fell by 17 for GET and 27 for both POSTs.
Both backends preserved corpus outcomes, blocking traces and full audit records.
The [report and samples](https://github.com/phihos/zentinel-modsec/blob/measure/full-crs-snapshot/benches/results/crs-round6/RESULTS.md)
include multipart, denied-method and high-header-count measurements.

## Filename and header checkpoint at `c14c323`

Engine `c14c323` follows `e0579b6`. It reuses the decoded filename and frequently
selected headers across rules, prepares literal TX defaults in replay order, and
reduces allocation for audit records and macro expansion. On OWASP CRS 4.25.0
(698 rules), eight Criterion pairs measured 7.8% lower GET latency, 6.1% lower
form POST latency and 2.8% lower nested JSON POST latency. A second, interleaved
measurement improved all three in every pair. Across 18 mixed-traffic pairs,
Rust p99 moved from 156.0 to 152.8 µs. Optional C p99 was effectively flat.

Each request allocated 2,101–2,155 fewer bytes with audit getters unread. Loading
the full ruleset took 1.8% longer and retained an additional 10,023 bytes.
JSON POST to a percent-encoded UTF-8 path measured 0.9% slower. Both detector
backends retained corpus outcomes, blocking traces and ordered audit data.
The [benchmark report and raw samples](https://github.com/phihos/zentinel-modsec/blob/measure/full-crs-snapshot/benches/results/crs-round5/RESULTS.md)
include the dependency lockfile, workload definitions, verification and timing details.

## Short argument and phrase checkpoint at `41e047f`

Engine `41e047f` follows `e7cd1d3`. It summarizes short argument names and values
once per eligible phase, skips regex and phrase targets that cannot match, and
reuses request lines up to 4 KiB when several rules read them. On the 698-rule
OWASP CRS 4.25.0 benchmark, median paired request latency fell 18.5% for GET,
17.2% for form POST and 16.0% for nested JSON POST. All eight pairs improved
for each workload. On 24 mixed fixtures, Rust p99 fell from 177.7 to 152.6 µs
and optional C detector p99 from 170.2 to 151.0 µs. The 65-byte value,
33-field form and non-ASCII JSON checks improved by 4.1–9.3%.
Both detector backends retained corpus outcomes, blocking traces and full audit
records. The [benchmark report and samples](https://github.com/phihos/zentinel-modsec/blob/measure/full-crs-snapshot/benches/results/crs-round4/RESULTS.md)
include fresh-load timings, allocation counts and differential comparisons.

## Audit allocation and transformation checkpoint at `9762969`

Engine commits `32f40b6`, `7c1cf5b` and `9762969` defer fixed phase-one audit
records, skip transformations proven to preserve a field, and reject short
alphanumeric values that cannot match a regex. Against the previous fork
checkpoint `573f9bc`, the 698-rule OWASP CRS 4.25.0 benchmark measured paired
latency reductions of 4.4% for GET, 4.8% for form POST and 8.8% for nested JSON POST.
Rust p99 on the 24 mixed fixtures fell from 191.4 to 181.9 µs. Fresh full-CRS
loading measured 272.2 to 274.5 ms. Both detector backends retained the corpus
outcomes, blocking traces and audit records. The [benchmark report and samples](https://github.com/phihos/zentinel-modsec/blob/measure/full-crs-snapshot/benches/results/crs-round3/RESULTS.md)
include allocations for callers that read audit data early, late or never.

## Phase-one defaults and regex checkpoint at `2725d4b`

Engine commits `d410f28` and `2725d4b` prepare deterministic phase-1 TX defaults
and avoid regex searches on inputs that cannot match. Compared with the previous
engine at `a213869`, eight paired runs of the 698-rule OWASP CRS 4.25.0 benchmark
showed 11.2% lower latency for GET, 9.8% for form POST and 15.5% for nested JSON POST.
A second measurement interleaving warmed workers improved all three in every pair.

Across 24 mixed fixtures, default Rust p50 went from 163.2 to 155.2 µs and p99
from 203.6 to 186.5 µs. Fresh full-CRS loading measured 279.4 to 277.5 ms.
Both detector backends retained the same corpus outcomes, blocking traces and
complete audit records. The final regex differential found zero mismatches in
20,044,080 comparisons. The [local report and raw measurements](benches/results/perf-regex-followup/RESULTS.md)
include the workload definitions, process-pair results and concurrent checks.

## Regex match-width checkpoint at `a213869`

Engine `a213869` computes minimum regex match widths while compiling each expression.
Against `9fa45f6` on the 698-rule CRS benchmark in upstream PR #69, warmed GET went
from 73.9 to 64.1 µs, form POST from 87.6 to 77.7 µs and nested JSON POST from
109.7 to 104.9 µs. Each improved in all eight process pairs. On 24 mixed fixtures,
default Rust p50 went from 177.2 to 161.5 µs and p99 from 218.9 to 204.7 µs.
Fresh full-CRS loading went from 265.4 to 273.9 ms.

Both detector backends retained the external corpus outcomes, 22 blocking traces
and 24 full audit records. The local [report and raw measurements](benches/results/perf-post-grouped/RESULTS.md)
identify the benchmark revisions and the separate cold-load and regex checks.

## Request target and TX checkpoint at `3594fa0`

Engine `3594fa0e54d275449a59e165765438e34bdd0f15` on `spike/crs-parity` scans request-target
delimiters and copies plain path spans directly. Numeric TX rules can reuse a
verified collection position for the four most frequently compared keys per
phase. The engine also borrows the request media type, tracks the active chain
by its starter, and renders a binary audit value directly into the public
record when one other snapshot holds the bytes and the cached display is cold.

Against `a22d582` on the warmed 706-rule configuration, GET p50 moved from
53.02 to 50.68 µs and form POST from 129.34 to 126.30 µs, each lower in eight of
eight pairs. A complete GET with an 8 KiB plain path moved from 394.53 to 362.64 µs,
lower in all six pairs. Mixed GET, form and JSON p50 moved from 181.18 to
175.35 µs on the Rust detector. In a single-rule workload, auditing
a 64 KiB predominantly high-bit header moved from 241.97 to 54.49 µs.
With 256 comparisons against four recurring TX keys, p50 moved from 10.95 to 6.66 µs.

Both detector backends reproduced the pinned corpus outcomes, all 22 ordered
blocking traces and the previous engine's audit bytes on all 24 mixed fixtures.
All 13 repository checks passed. The two builds also returned identical bytes
for all observed request fields and arguments in 60,000 generated cases.
The [local benchmark report](../zentinel-eval/results/latency-499db21/RESULTS.md)
includes separate measurements for request-target parsing and complete request
inspection, plus the audit and TX controls, raw samples and verification records.

## TX evaluation and rule removal checkpoint at `a22d582`

Engine commit `a22d582f1d172bbaa9a47467c7bdb8d4e440b725` evaluates single-key static numeric
TX comparisons directly and prepares literal `setvar` assignments at load time.
Active rule ID removals form a sorted set of disjoint ranges within each
transaction. The binary audit formatter can copy long printable runs after
checking whole blocks for bytes that require escaping.

Against `b8bc7e5` on the same warmed 706-rule configuration, GET p50 moved
from 60.55 to 53.82 µs and form POST from 139.26 to 135.41 µs, each faster in all
eight pairs. Mixed GET, form and JSON p50 moved from 208.34 to
200.73 µs and p99 from 751.36 to 665.51 µs.
With 64 active removal ranges, GET p50 moved from 224.67 to 70.94 µs.
Reading a 65,530-byte header with one non-ASCII byte into the audit record
moved from 123.25 to 92.37 µs at p50. Without the audit read, p50 rose from
5.63 to 7.50 µs in workers alternating between audit reads and skips. In workers that
never read audit data, the same header moved from 7.29 to 5.44 µs. On the same-sized header with
a non-ASCII byte every ten bytes, p99 moved from 200.05 to 213.37 µs.

All 13 repository checks passed. Both detector backends reproduced the
pinned Coraza corpus outcomes, all 22 ordered blocking traces and the
previous engine's full audit records on 24 mixed fixtures. The
[local benchmark report](../zentinel-eval/results/latency-3466fed/RESULTS.md)
includes raw timing receipts, resource measurements and verification.

## Binary audit and collection checkpoint at `b8bc7e5`

Engine commit `b8bc7e56c13d1a19e8e02818b6e4ee30272bd64f` on
`spike/crs-parity` renders binary audit values in blocks and shares large
text buffers across transaction snapshots. Collection exclusions run once
per canonical key. Negated static regex rules use a single existence check.

Compared with `20ee858` in the same warmed benchmark, full-CRS GET p50 fell
from 62.31 to 59.75 µs and form POST from 145.80 to 134.14 µs, both faster in
all eight pairs. Mixed GET, form and nested JSON p50 moved from
205.97 to 190.56 µs and p99 from 318.84 to 317.60 µs.
Reading a matched 65,530-byte binary header into the audit record fell
from 255.42 to 138.01 µs at p50 and from 282.26 to 157.50 µs at p99.
An unmatched valid-text header of that size cost one extra 72-byte allocation.
All 13 checks passed. Both detector backends reproduced the pinned corpus
outcomes, the 22 ordered blocking traces and all 24 mixed-request audit fixtures.
The [local benchmark report](../zentinel-eval/results/latency-1c46c6e/RESULTS.md)
includes sample counts, audit-read results, allocation and ruleset memory costs.

## TX and matched rule checkpoint at `20ee858`

Engine commit `20ee8581ff172f6d359223d5373afe581b272b63` on
`spike/crs-parity` uses ordered scalar storage for TX, prepares eligible
rule targets per phase and reuses the inspected bytes for successful static
numeric comparisons. Match records retain their compiled rule positions,
and a single matched ID can be read directly from the ruleset.

Compared with `92a6e0b`, warmed full-CRS GET p50 fell from
124.64 to 99.33 µs and form POST from 266.14 to 236.89 µs. The mixed GET,
form and nested-JSON workload moved from 225.58 to 206.04 µs at p50 and from
297.13 to 277.15 µs at p99. GET allocations fell from 427 to 220, and form POST
allocations from 627 to 430. On the single-rule fixture that reads the full
65,530-byte binary header into an audit record, resident-worker p50 rose
from 238.55 to 264.20 µs. Form POST with an audit read improved at p99 in
four of eight rounds. All 13 repository checks passed. Both
backends preserved the pinned corpus outcomes, all 22 blocking traces and
the complete mixed-request audit evidence. The
[local qualification report](../zentinel-eval/results/latency-fe6d1ea/RESULTS.md)
includes audit-read timings, one-rule measurements and ruleset memory.

## Short-value and rule evaluation checkpoint at `92a6e0b`

Engine commit `92a6e0bd0de0fd9ba4f803c50b419dc6b75acfe1` on
`spike/crs-parity` stores short text inline, shares binary match evidence
and formats its escaped text on demand. The evaluator resolves targets
in place, skips collections removed by tag controls, and reduces dispatch
cost for empty and single-stage byte transformation pipelines.

Compared with `df9f095` on the same full CRS, default Rust GET p50 fell
from 89.03 to 78.11 µs and form POST from 191.34 to 165.04 µs. Both
improved in all eight paired rounds, including with audit data read on every
request. The mixed GET, form and nested-JSON workload fell from 261.02 to
227.03 µs at p50 and from 329.34 to 308.63 µs at p99. GET allocations fell
from 792 to 427 and form POST from 1,056 to 627. All 13 repository checks
passed. Both backends reproduced the pinned corpus outcomes, blocking
traces and complete mixed-request audit evidence. The
[local performance and correctness report](../zentinel-eval/results/latency-a11fb89/RESULTS.md)
includes the workload definitions, full distributions and binary-input results.

## Selector and audit checkpoint at `df9f095`

Engine commit `df9f095d9a804fc68ab7f259218899b0d2e90c19` on
`spike/crs-parity` prepares collection selectors after configuration updates,
skips empty collection resolution, visits scalar values directly and builds
public audit records on first access. Raw matched evidence remains available
across phases.

Compared with `0895015` on the full CRS, default-backend GET p50 fell from
114.35 to 88.37 µs and form POST p50 from 215.69 to 188.46 µs. P50 and p99
improved in all eight rounds alternating warmed workers every 64 requests,
including when every request read its audit data. In a separate 24-request
mix of GET, form POST and nested JSON, p50 fell from 300.23 to 270.18 µs
and p99 from 524.67 to 487.42 µs. Whole-process p99 was more variable on
the shared host. Both backends reproduced the pinned corpus outcomes, all
22 blocking traces and complete mixed-request audit evidence. The
[local latency report](../zentinel-eval/results/latency-841b4eb/RESULTS.md)
contains the measurements, allocation counts, ruleset memory cost and
source-bound verification.

## Request latency checkpoint at `0895015`

Engine commit `08950153e71fbb68e03c57fca5acec6643bddf73` on
`spike/crs-parity` moves static rule decisions to configuration loading and
avoids reprocessing short inputs when all built-in transformations preserve
every byte. It also reduces work in collection lookup, regex evaluation and
URL decoding.

Compared with `e6b3518`, the default Rust engine's full-CRS median p50 fell
from 146.15 to 114.20 µs for GET and from 291.20 to 217.25 µs for form POST.
Both workloads improved in all eight counterbalanced pairs. Median p99 fell
from 170.35 to 138.55 µs for GET and from 366.20 to 246.95 µs for form POST.
These are warmed, in-process measurements. Both backends matched the existing
CRS corpus outcomes and all 22 blocking traces. The
[local qualification report](../zentinel-eval/results/latency-3ba717e/RESULTS.md)
contains samples, workload definitions and build receipts.

## Configuration, whitespace and count checkpoint at `e6b3518`

Engine commit `e6b3518baa37cebe30a1e1e625082ac89f73b0cf` on
`spike/crs-parity` fixes configuration loading around comments, whitespace
and includes. Failed appends to a reusable parser restore its previous rules
and phase defaults. The loader now enforces Coraza's limit of 100 cumulative
`Include` directives per configuration.

The `compressWhitespace` transformation matches Coraza on 350 text and
binary fixtures. Static count rules delay creating the target name until a
match needs it. On warmed full-CRS requests, allocator-requested bytes fell
from 70,431 to 59,120 per GET and from 80,469 to 68,354 per form POST.
Both backends reproduced the baseline native stages and the external Coraza
corpus outcomes and blocking traces. The [local qualification report](../zentinel-eval/results/engine-cfa97fe/RESULTS.md)
contains the comparison inputs, performance measurements and limits.

## Rule updates and validators checkpoint at `8692a95`

Engine commit `8692a953e2bc51c672391bd720be95bef4c661fb` on
`spike/crs-parity` implements single-ID `deny`, `pass` and `status` rule
updates, checks byte-range declarations, and fixes response-length and
directory-basename resolution. Macro expansion borrows first collection
values. Boolean libinjection calls avoid constructing owned fingerprints.

The default Rust and optional C builds matched Coraza 3.8.1 on every CRS
4.25.0 case outcome and all 22 blocking traces. Warmed full-CRS allocations
fell from 1,426 to 1,299 per GET and from 2,037 to 1,878 per form POST.
The [local qualification report](../zentinel-eval/results/range-5a6021b/RESULTS.md)
records the accepted rule-update subset, known corpus failures, timing
distributions and the source-bound receipts.

## Rule semantics and capture checkpoint at `e532df5`

Engine commit `e532df5c83c67ee4996d2b698444fc1621e4d596` on `spike/crs-parity`
adds scoped allow actions, file-backed operator aliases, ordered phrase
captures, ModSecurity word matching and IPv4-mapped network handling. Capture
storage moves owned bytes into transaction slots. Both detection backends
passed the repository gates and matched the prior CRS outcomes and blocking
traces. The [local qualification report](../zentinel-eval/results/rules-6a8f8a5/RESULTS.md)
records the performance measurements and remaining reference differences.

## Rust detector checkpoint at `3910553`

Engine commit `391055367c54e6a3e307fb6b6ceac84fe0725603` on
`spike/crs-parity` uses a pure-Rust libinjection port by default. The optional
C backend remains available. Both backends produced identical outcomes on every
stage of the pinned CI corpus and matched Coraza 3.8.1 on the CRS 4.25 suite
and the 22 blocking cases. The reference fixture run also compared detector
verdicts and SQL fingerprints on 167,646 upstream inputs.

The same commit implements transaction-local rule removal by tag and reduces
allocations for rule target evaluation, regex searches and action processing.
The [local qualification report](../zentinel-eval/results/impact-ff45140/RESULTS.md)
contains measurements, limitations and links to the frozen receipts.

## Original checkpoint at `11abeffc`

The requested measured parity goal is complete for Coraza **3.8.1**, OWASP CRS
**4.25.0**, and the specified GET/form-POST workloads. This qualifies a local
candidate; production integration, concurrency/reload behavior, other CRS
versions and every Coraza feature remain outside the evidence.

At `11abeffc`, the parity build required **`libinjection-ffi`**. The
then-default Rust heuristic fell short of the reference on that checkpoint.

## Checkpoint and working state

- Repository: `/home/phil/Quellcode/zentinel-modsec`.
- Branch: `spike/crs-parity`.
- Qualified code commit: `11abeffc0f0298e33862fd06a43369af05f859d6`.
- Qualified Git tree: `33bc590b1b85a8f40b6b6450cb1cbac15105dc21`.
- Original evaluation baseline: `f85a240`.
- Original item-5 stopping checkpoint: `7f365d1bead8c1e85521d9a6f67307851fc78d98`.
- This handoff is a documentation-only follow-up to the qualified code commit.
  The qualification receipts continue to identify `11abeffc`.
- Main and all listed agent worktrees were clean when preparing this handoff.
  The completed validation recorded no active owned benchmark/test processes.
- Nothing was pushed, published, deployed or submitted as a PR. No hosted CI
  campaign or external contact occurred.

The original spike obeyed its item-5 stop gate. The later goal authorized
continuing to parity. Preserve that history rather than interpreting the first
report as the current result.

## Read these first

1. [Final parity report](/home/phil/Quellcode/zentinel-eval/results/parity-goal/PARITY_REPORT.md):
   changes, commit/test mapping, measurements, shared failures and limits.
2. [Final delivery receipt](/home/phil/Quellcode/zentinel-eval/results/parity-goal/final-delivery.json)
   and [completion audit](/home/phil/Quellcode/zentinel-eval/results/parity-goal/completion-audit.json).
3. [Blocking comparison report](/home/phil/Quellcode/zentinel-eval/results/parity-goal/final-blocking-matrix/REPORT.md).
4. [Original prompt](/home/phil/Quellcode/zentinel-eval/CODEX_PROMPT.md)
   and [historical spike report](/home/phil/Quellcode/zentinel-eval/SPIKE_REPORT.md).

The historical report is unchanged, SHA256
`52b78218236816d37c2789b377efa2db57094325103183a4dde1df7f158d1451`.
All 16 entries in `final-artifact-hashes.json` were read back and verified while
preparing this handoff.

## Verified result

| Check | Zentinel | Coraza |
|---|---:|---:|
| CRS cases passed / executed | 4,655 / 4,672 | 4,655 / 4,672 |
| Failed case IDs | Same 17 | Same 17 |
| Additional zentinel failures / PL1 false negatives / PL1 false positives | 0 / 0 / 0 | Reference |
| Blocking matrix | All 22 exact comparisons | Reference |
| Hot GET median p50 | 281.0 µs | 312.7 µs |
| GET at 50 req/s median p50 | 403.5 µs | 436.4 µs |
| Hot form POST median p50 | 682.3 µs | 766.3 µs |
| Form POST at 50 req/s median p50 | 917.0 µs | 922.5 µs |
| Extra ruleset memory, different tenant exclusions | 1.798 MiB RSS | 1.877 MiB RSS / 2.054 MiB heap |

Latency uses three interleaved repetitions, 20,000 hot requests or 1,000 paced
requests per run. The paced POST difference is within overlapping noise; describe
it as parity. All observations, including a noisy repetition, are retained.
Memory uses three repetitions at 1, 4 and 16 retained engines, both identical
configs and distinct exclusions; the incremental slope is `(engine16-engine1)/15`.

The corpus runs DetectionOnly at PL4. The separate blocking matrix runs On at
PL1 with the complete pinned recommended/setup/CRS configuration. All 22
comparisons match intervention status, every score-named TX key/value, and ordered
rule IDs after phases 1, 2 and 5. It includes benign requests, attacks in multiple
body formats, malformed bodies and the exact request-body limit. Malformed
JSON/XML/multipart return 400; the exact 13,107,200-byte limit returns 413.

Both engines have one additional client-side errored file: go-ftw refuses to
construct a structured header containing raw CR/LF. Do not report 100% corpus
success or silently remove this limitation.

## What changed

The historical report details the first five priorities: corrected
`normalizePathWin`, optional statically compiled upstream C libinjection,
full-width decoding, tag target exclusions and shared compiled regexes.

The continuation landed separate commits for the following work. The final
report lists the full commit-to-regression mapping.

| Area | Main commits / effect |
|---|---|
| Request execution | `8be9dd0`: borrow immutable phase rules instead of deep-cloning them per request. Allocation regression coverage prevents the old cost returning. |
| Original bytes | `e1e831d`, `e95e80f`, `f961d01`, `dff9b36`: retain binary keys/values through collections, transforms, operators, captures and macros; display strings never become detection input. |
| Normalization and regexes | One-pass URL plus/percent handling; full 370-entry Unicode best-fit map; decoded filenames with raw URI retained; native escape/Base64/CSS/JS behavior; correct regex flags, binary captures and braced byte escapes. |
| Rule semantics | TX selector folding without corrupting regex syntax; argument macros; `multiMatch` on the original and every changed stage; quoted numeric IDs. |
| XML | Separate text/attribute collection instead of synthetic HTTP arguments or raw markup. Streaming/entity/error behavior retained. General XPath was not added. |
| Multipart | `5352162`, `ad6779a`, `38abca3`, `f7dcdff`: byte-safe framing, quoted/extended/continued parameters, real FILES collections and sizes, strict/parser errors, quoted-printable and folded-header controls. Closed all 18 remaining multipart detection misses. |
| Body policy | `4299a8e`: bounded acquisition, access/MIME policy, Reject/ProcessPartial, explicit prefix counts and once-only phases 1–4. |
| Metadata and logs | Actual response status/protocol; first Content-Type processor selection before phase 1; original header spelling with canonical lookup; opt-in match-time message/logdata snapshots. |
| Numeric behavior | `90c71b8`: pinned signed-64 conversion for empty, malformed, binary and overflow inputs. Eliminates false benign-request denial at recommended rule 200003. |
| Scores | `abfef70`: preserve rule-owned TX scores; remove stale cache writes that reset category scores to zero and create absent variables. |
| Logging/status | `085a021`, `ed61ada`: phase 5 after denial, pinned repeated/allow/disruptive behavior, explicit status actions, redirect and drop semantics. |
| Arithmetic safety | `11abeff`: explicit wrapping for setvar/collection arithmetic; captured request values no longer trigger signed-overflow panics. Recorded operands remain exact. |
| Memory | `8050c98`: share immutable phrase automata and phrase lists by exact parsed content, with weak lifetimes and concurrent-load tests. Extra ruleset RSS fell from about 9 MiB after regex sharing to about 1.8 MiB. |

Broader shared-rule-program/sparse-exclusion redesign was investigated and held.
Public `CompiledRule` fields and `rules_for_phase() -> &[CompiledRule]` complicate
that design; PM sharing already met the memory target.

## API details an integrator must preserve

- Request and response body access default to **Off**, matching the reference.
  Enable the required access and response MIME types explicitly.
- Prefer byte input APIs for opaque input. String/display representations of
  binary data must not be fed back into matching.
- `write_request_body` / `write_response_body` expose the retained-prefix count
  and completion state. Old append wrappers remain, but a connector must retain
  the original bytes for forwarding and check interventions.
- Supply actual response metadata with
  `process_response_headers_with_status(status, protocol)`.
- `set_record_rule_messages(true)` enables original-byte `msg`/`logdata`
  snapshots. Recording is off by default; the connector owns logging policy and
  escaping. A standalone rule's primary message retains its first match.
- `anomaly_score()` reads legacy `TX:anomaly_score`. For this CRS, read
  `TX:blocking_inbound_anomaly_score` and relevant per-paranoia TX variables.
- Phase 5 deliberately matches pinned Coraza: it runs after denial, repeated
  calls rerun actions, `allow` suppresses it, and a disruptive logging rule can
  replace an earlier intervention while later logging rules still run.
- Default `drop` has status **0** and `drop_connection=true`. Test whether an
  intervention/drop exists; a nonzero HTTP status is not the only block signal.

## Evidence and harness traps

Evidence root:
`/home/phil/Quellcode/zentinel-eval/results/parity-goal`.
Working harness cache:
`/home/phil/Quellcode/zentinel-build-cache/goal-harness`.

| Evidence | Purpose |
|---|---|
| `final-v2-receipt.json`, `final-v2-classification.json`, `final-v2-zentinel.log.*`, `v2-pinned-baseline-coraza.*` | Source/binary/config hashes, real command exits and exact complete corpus sets. |
| `final-blocking-matrix/manifest.json`, `final-comparison.json`, trace sources and compressed inputs | Full blocking comparison and pinned source provenance, including all 51 rules/data/config files. |
| `final-local-checks.json`, `final-*.out/err` | Eight completed local checks. |
| `final-latency-complete.json`, `final-latency-summary.json`, terminal receipt | All 24 completed timing observations. `final-latency.json` is only the retained first five observations from an interrupted session. |
| `final-memory.json`, `final-memory-summary.json` | All 36 memory runs, including different exclusions and separate Coraza heap/RSS metrics. |
| `final-libinj-receipt.json`, `final-libinj-summary.json` | Fresh final-source three-repeat FFI/API cost campaign; public API medians about 0.149–0.551 µs across four inputs. |
| `final-load-inventory.err`, summary JSON | Visible unsupported/approximated features and affected rule IDs. |
| `final-artifact-hashes.json` | Seal for the 16 primary final artifacts. |

Use **adapter V2.1** and the final archived sources in
`final-adapter-source-worker-v2/` and `final-adapter-source-ftw-v2/`. The original
evaluation adapter discarded response status, lost invalid UTF-8 URI/header bytes
through JSON strings, and emitted IDs without real expanded logs. V2.1 transports
bytes as base64, supplies actual metadata and reads logging policy from compiled
actions. It fixes the adapter rather than fabricating expected messages. The
larger final case denominator reflects three previously aborted response cases.

Use the quoted recommended config **bundled with coraza-coreruleset v4.25.0**:

```
/home/phil/go/pkg/mod/github.com/corazawaf/coraza-coreruleset/v4@v4.25.0/rules/@coraza.conf-recommended
```

The recommended config in `coraza/v3@v3.8.1` is newer and includes additional
unsupported variables/directives. Experiments selecting it fail visibly and are
not parity evidence. Do not substitute it accidentally.

The low timings in `pilot-v2` are **invalid**: benign requests were rejected at
rule 200003 after 44 matches instead of continuing to the reference's 62. The
numeric fix and exact blocking trace resolved that shortcut. Final benchmark
counts before logging are GET **62** and POST **61** in both engines.

The go-ftw runner can exit zero while cases fail. Read classifications, missing
Coraza successes, raw failed/errored IDs and command receipts together. Also use
distinct Cargo package/binary names for adapter variants; an early same-name
shared-target experiment selected the old binary.

## Resume commands

Revalidate only when source or an unresolved concern warrants it. These checks
passed on the frozen code. The handoff itself is documentation-only.

```sh
cd /home/phil/Quellcode/zentinel-modsec
git status --short
git log -1 --oneline
cargo fmt --check
git diff --check
CARGO_BUILD_JOBS=2 SKIP_CRS_CONFORMANCE=1 cargo test --all-targets
CARGO_BUILD_JOBS=2 SKIP_CRS_CONFORMANCE=1 cargo test --features libinjection-ffi --all-targets
CARGO_BUILD_JOBS=2 cargo clippy --all-targets -- -D warnings
CARGO_BUILD_JOBS=2 cargo clippy --features libinjection-ffi --all-targets -- -D warnings
env -u SKIP_CRS_CONFORMANCE CARGO_BUILD_JOBS=2 CRS_DIR=/home/phil/Quellcode/zentinel-eval/results/parity-goal/native-crs-4.25 cargo test --features libinjection-ffi --test crs_conformance stock_crs_blocks_attacks_and_passes_ordinary_traffic -- --nocapture
CARGO_BUILD_JOBS=2 RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --features libinjection-ffi
```

The native corpus gate is for a different CRS pin (main/4.31), with exact
`MIN_PASSING=4900` and `EXPECTED_SKIPS_MAX=60`. It was **not qualified** in this
campaign. The unit-job skip above is explicit; the pinned go-ftw corpus and the
separate stock blocking test provide the 4.25 evidence. Before upstream CI work,
test its actual pinned corpus and review any changed count. Do not lower a gate
or edit expectations to hide a regression.

After committing a future source candidate, use fresh result prefixes:

```sh
PARITY_EVIDENCE=/home/phil/Quellcode/zentinel-eval/results/parity-goal
python3 "$PARITY_EVIDENCE/checkpoint-v2.py" next-candidate-001
# Inspect next-candidate-001-receipt.json and classification before timing.
python3 "$PARITY_EVIDENCE/benchmark-v2.py" next-latency-001 "$PARITY_EVIDENCE/bin/worker-next-candidate-001" 20000 1000 3
python3 "$PARITY_EVIDENCE/memory-v2.py" next-memory-001 "$PARITY_EVIDENCE/bin/worker-next-candidate-001" 3
```

Do not compile or run other owned CPU-heavy work during latency measurements.
If interrupted, inspect the actual process/PID and receipts; do not duplicate a
confirmed-live job. Preserve partial evidence and resume only missing work.

The checkpoint helper depends on the working harness cache and a target directory
under `/tmp`. If those disappear, restore working copies from the final archived
adapter sources, rebuild `ftw-v2.1`, and explicitly review its absolute paths.
Never edit the archived final sources/results in place. The blocking matrix
report provides reproduction commands; decompress its `cases.json.gz` in a fresh
copy first. Manifests bind the actual decompressed input.

## Limits and recommended next work

No work remains for the stated measured acceptance criteria. Adoption still
needs a separate, representative integration/traffic and concurrency/reload
qualification. No installed HAPTIC/cgo replacement or production deployment has
been tested. Upstream submission/release is not authorized by the completed work.

Known feature gaps remain visible through warnings/errors: `SecRuleUpdateActionById`,
in-memory body spooling/no-files limits, configurable JSON depth, general XPath,
persistent collections/audit storage, `UNIQUE_ID`, and the documented `@within`
approximation. Tag **target** exclusions are implemented; do not confuse them
with unsupported `ctl:ruleRemoveByTag`. Custom XML DTD/entities remain literal
with an error; no external entity resolution was added. C libinjection and the
pinned Go port differ on two XML/XInclude inputs, so universal semantic identity
is not claimed.

The same 17 failures remain in both corpus runs: 13 protocol/front-end
status/log expectations, one Apache-specific duplicate Content-Type assumption,
and three multipart diagnostic-text expectations. Malformed multipart blocking
is independently verified. The final report lists every ID. Do not remove these
tests or invent matching diagnostic output to raise the pass count.

If asked to continue: first read the report and verify current state; then choose
either integration qualification, an upstream review/CI series, or a concrete
unsupported feature required by the deployment. Keep those scopes explicit.

## Constraints and remaining worktrees

- No Lua in the engine, harness or workaround.
- Never weaken detection, skip cases or edit pinned CRS rules/expectations to
  improve results. Unsupported execution must remain visible.
- Keep fixes in separate reviewable commits with meaningful regressions.
- Original `zentinel-eval` inputs/scripts and historical reports are preserved;
  add new results rather than overwriting old evidence.
- No push, PR, contact, publication or deployment without a new request.
- Use quick focused tests and parallelize independent work, while keeping timing
  campaigns free of owned compilation contention. No admin commands were needed.

Isolated worktrees remain under `/tmp/zentinel-goal-*` and
`/tmp/zentinel-spike-*`; persistent build caches are under
`/home/phil/Quellcode/zentinel-build-cache`. `git worktree list` is authoritative.
All essential changes are already integrated into `spike/crs-parity`; agent SHAs
often differ after cherry-picking. Do not blindly cherry-pick the remaining
branch heads. No cleanup/removal of those worktrees was performed for this handoff.
