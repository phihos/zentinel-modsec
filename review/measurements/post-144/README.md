# Where the fork saves request time

On clean CRS requests, two of the largest measured differences were the cost of constructing short strings for repeated matches and the cost of searching inputs that cannot contain any configured phrase. On the fork, routing nonempty short values through heap storage increased unread GET, form and JSON latency by 28.7%, 23.2% and 20.7%. The three median times went from 37.9 to 48.6 µs, 47.4 to 58.8 µs and 55.4 to 67.4 µs. This experiment changes storage and the corresponding construction paths together. [Ablation patch](disable-short-values.patch) · [Paired samples](short-ablation.json)

## Final comparison after porting dotted-word bounds

The fork computes separate minimum match lengths for names made of ASCII letters, digits and dots. Clean JSON supplies names such as `json.items.0.sku`. A regex or phrase that requires a slash, colon or other punctuation cannot match such a name. The planner can skip that target before transforming or searching it.

Disabling just the dotted bound on the fork increased JSON from 56.42 to 60.98 µs unread and 74.41 to 79.28 µs read. The median paired increases were 6.57% and 6.42%. Adding the same distinction to #149 reduced integrated JSON latency by 7.07% unread and 5.99% read. The extra classification cost 1.22% on GET and 1.90% on form unread in that comparison. [Fork ablation](dotted-attribution.json) · [Ablation patch](disable-dotted-width.patch) · [Integrated pairs](dotted-increment.json)

| Matched data | Build | GET µs | Form POST µs | JSON POST µs |
|---|---|---:|---:|---:|
| Unread | #137–149 together | 38.3 | 49.6 | 57.3 |
| Unread | Fork | 38.9 | 48.9 | 57.7 |
| Read at end | #137–149 together | 48.4 | 60.2 | 68.0 |
| Read at end | Fork | 57.7 | 66.8 | 75.1 |

This confirmation repeats eight alternating process pairs on CPU 12. Medians of within-pair differences (integrated minus fork) were −0.65, +0.67 and +0.12 µs unread. In the first eight pairs they were +0.10, +1.80 and +0.24 µs. Both runs put JSON close to parity and form slightly ahead on the fork. Reading matched data favored the integrated build on all three fixtures in both runs. [First run](dotted-gap.json) · [Confirmation](dotted-confirm.json)

The updated #149 alone reduced unread GET, form and JSON latency by 4.5%, 4.9% and 7.5% against upstream main. All 10,368 public audit snapshots still agreed with main for #149 and the combined build. [Standalone pairs](dotted-standalone.json)

## Before the dotted-word change

Each cell is a median of eight process means in µs per request. Both builds use 698 rules from CRS 4.25.0. Each process warms up before measuring 2,200 transactions per fixture. Build order alternates within each pair on CPU 12. The integrated build contains the thirteen performance changes, with #149 at its first commit, based on upstream 0.13.3. The fork is at `3d1fd5c`. The [paired samples](phrase-gap.json) also support computing median within-pair ratios, which can differ from ratios of the table entries.

| Matched data | Build | GET | Form POST | JSON POST |
|---|---|---:|---:|---:|
| Unread | #137–149 together | 37.7 | 47.5 | 60.2 |
| Unread | Fork | 38.1 | 48.2 | 56.3 |
| Read at end | #137–149 together | 47.1 | 58.0 | 70.7 |
| Read at end | Fork | 56.5 | 65.2 | 74.2 |

Upstream main at `a3a5f2c` measured 63.1, 75.6 and 84.0 µs unread in the [previous comparison](../post-140/). Those timings used CPU 14. This host is shared. Small differences on GET and form should be interpreted accordingly.

## What the individual changes saved

| PR | Measurement |
|---|---|
| #145 | With #137–144 included on both sides, reusing numeric comparisons and audit entries on unchanged shared TX defaults reduced unread GET, form and JSON latency by 14.1%, 12.7% and 10.0%. Allocations and reallocations per warmed request fell from 406/520/529 to 289/404/414. The fork used 108/146/157. [Paired times](numeric-increment.json) |
| #146 | Skipping discarded regex captures saved 18.8%, 56.0% and 65.1% on phase-one fixtures with 1, 16 and 64 negated regex rules. On the nine-PR CRS baseline it saved 1.4–1.6% unread. [Focused pairs](focus.json) · [CRS pairs](residual-candidates.json) |
| #147 | Borrowing macro values saved 3.5% and 5.7% on fixtures with 16 and 64 macro-expanding rules. The unread CRS reductions on the nine-PR baseline were 3.9%, 2.9% and 2.1%. [Focused pairs](focus.json) · [CRS pairs](residual-candidates.json) |
| #148 | Storing the first collection value inline saved 8.3% and 14.5% with 16 and 64 distinct extra query arguments. On the nine-PR CRS baseline, GET and form were 1.0% and 0.2% slower and JSON was 1.6% faster unread. [Focused pairs](focus.json) · [CRS pairs](single-attribution.json) |
| #149 | Applying alphabet-specific phrase lengths before transformations and searches saved another 7.5%, 9.8% and 4.4% unread on top of the first twelve changes. Directly against main it saved 7.3%, 7.8% and 4.7%. [Incremental pairs](phrase-increment.json) · [Standalone pairs](phrase-standalone.json) |

The changes interact. Their percentages use different baselines and cannot be added. The focused results use ten alternating process pairs and 4,000 transactions per fixture. [Focused harness](residual_focus.rs) · [Full workload and instructions](../post-140/)

## Locating the JSON difference before the dotted-word change

Separate timing around the public transaction methods on CPU 14 measured 36.23 µs for appending and processing the JSON request body on the combined build and 31.24 µs on the fork. Logging took 2.41 vs 1.08 µs. The body interval includes parsing and phase-two rule evaluation. Instrumentation changes absolute times. [Phase samples](final-phases.json) · [Phase harness](phase_cost.rs)

For the combined build and each new PR separately, all 10,368 after-header and after-body snapshots matched upstream main byte for byte for matched IDs, matched data, messages and interventions. Release conformance for each PR equaled main at 4,979 of 5,184 runnable cases, with 41 skipped. The fork has separate behavior changes. For example, on the timed GET and JSON requests it also records rule 901340. [PR head revisions](pr-heads.json)

The body interval with an empty object was 16.81 vs 15.66 µs. With two flat scalar fields it was 29.16 vs 24.30 µs, and with the nested fixture it was 35.68 vs 31.02 µs. Rules that explicitly match the nested SKU and quantity fired in both builds. Timing request construction, JSON parsing and destruction in isolation took 0.61 µs on the integrated build and 0.80 µs on the fork. Parsing alone cannot account for the fork’s lead. [JSON fixture samples](json-phases.json) · [Harness](json_cost.rs)

The fork exposes the raw request body to rules according to the selected processor. Upstream also exposes the raw JSON body. An experimental fork build exposed the raw body and its length during JSON inspection. The median paired JSON latency changed by +0.54% unread and −0.37% read. In a separate head-to-head comparison the fork with that change still took 56.83 µs vs 60.19 µs unread. Raw-body visibility alone explains little of the observed difference. The remaining time is concentrated in phase-two inspection with populated arguments. This observation led to testing the fork’s dotted-word bounds above. [Experimental change](expose-json-body.patch) · [Within-fork pairs](json-visibility.json) · [Integrated comparison](json-visible-gap.json)

The per-request allocator trace counts allocation, zeroed allocation and reallocation on one warmed request with matched data unread. On the eight-PR GET, repeated construction of matched values, rule IDs and successful numeric results accounted for 44, 42 and 30 calls respectively. [Allocator harness](alloc_probe.rs)
