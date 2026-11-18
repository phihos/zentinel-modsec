# Coraza rule and body compatibility

Runtime [`d840296`](https://github.com/phihos/zentinel-modsec/commit/d8402968e77d58a4e7dc7163e231a24129877d38) was compared with Coraza 3.8.1 and the previous fork checkpoint [`14eb6a0`](https://github.com/phihos/zentinel-modsec/commit/14eb6a0316fb429ea01cad86437c4b2dd50d4fa3).

| What a ruleset uses | What changed |
|---|---|
| Body limits | Request and response thresholds can change per transaction. The request memory threshold spills the acquired prefix into a temporary file. Phase 2 sees the same bytes in either storage mode. |
| Rule edits and lookups | Action updates support ID ranges and chain starters. Scalar and collection macros, named phrase/IP datasets, REST path arguments and national ID checks work through rule evaluation. |
| Body processors | A connector can select Coraza's explicit JSON/XML processor policy. Multipart rules that read `FILES_TMPNAMES` get decoded files until transaction drop. |
| Recursive JSON Schema | Deep validation uses heap-backed state for recursive object and array rules, including dynamic anchors, conditionals and references between local schema files. |

## Correctness

Both detector builds matched the complete Coraza CRS 4.25.0 case sets, including the same 4,655 passes, 17 failures and one fixture error. They matched every field compared in 22 blocking traces and retained all 24 Rust connector audit records byte-for-byte. The separate native CRS run reproduced every baseline stage outcome. [Qualification](qualification.json) · [Audit comparison](audit-changes.json)

All 48 transaction body-limit cases agreed on consumption, storage errors, flags and intervention status. On Linux both engines kept three bytes in memory, spilled when the next two arrived, parsed the complete form and released their file. All 17 processor and operator cases agreed on rule decisions and cleanup. Go also created two files for a metadata-only upload, while Rust created none. Action updates agreed on 34 of 35 cases. Rust rejects a negative status at load because its public intervention status is unsigned. Rust binds each named dataset to its declared contents when reloading. [Public API receipt](public-api/receipt.json) · [Dataset reference](datasets/reference-isolated.log)

Previously, nine valid deep documents produced false violations in the recursive test set. The final runtime matches all 48 pinned Go recursive cases and all eight scoped cases, accepts 10,000 nested arrays, and rejects 10,001 on a 1 MiB worker stack. A further 22 schema cases cover finite constraints, malformed JSON and uniqueness. The heap evaluator matched the existing Rust validator on 15,750 shallow decisions. For local companion files we checked against shallow Rust validation because the pinned Go configuration accepted an invalid external-reference example. [Before](recursive/before-ce3b0fc/receipt.json) · [Final results](public-api/receipt.json) · [Heap differential](recursive/graph-checks.json) · [External files](external/schema.json)

The default build passed 776 tests and the FFI build passed 778. The separately enabled libinjection test matched all 167,646 reference inputs. Formatting, strict Clippy and warning-denying documentation builds passed. Compressed logs retain their original SHA-256 when decompressed. [Source checks](source/receipt.json)

## Full CRS request latency

The benchmark loaded the 698 rules in OWASP CRS 4.25.0 and verified a blocking decision before timing the allowed GET, form POST and JSON POST requests. Sixteen interleaved pairs ran on two physical cores with 15,360 requests per workload per revision. Before and after values are medians across paired batches. The percentage is the median within-pair change. [Workloads](timing/full_crs.rs) · [Measurements](timing/comparison.json)

| Request | Wall time before → after | Paired change | Thread CPU before → after | Paired change |
|---|---:|---:|---:|---:|
| GET | 44.04 → 42.58 µs | −2.92% | 43.85 → 42.25 µs | −2.97% |
| Form POST | 57.18 → 54.03 µs | −4.84% | 56.53 → 53.06 µs | −4.68% |
| JSON POST | 65.29 → 64.29 µs | −2.51% | 64.83 → 63.78 µs | −2.55% |

Form POST used less thread CPU in 15 of 16 pairs. JSON used less CPU in 11 pairs, with a 0.25% improvement on the second core. Sibling threads were 27% and 40% busy on this shared host. These workloads measure normal CRS traffic. [First core](timing/pairs/summary.json) · [Second core](timing/repeat/summary.json)

## Replaying the public comparisons

From this evidence directory, use a clean checkout of the runtime commit with the supplied dependency lock. The verifier builds both libraries, reruns the Go reference programs and checks each Rust result. It writes the raw output and source receipt to a new directory. The file-descriptor observation runs on Linux.

```sh
git clone --branch spike/crs-parity https://github.com/phihos/zentinel-modsec.git /tmp/zentinel-rule-body-engine
git -C /tmp/zentinel-rule-body-engine checkout --detach d8402968e77d58a4e7dc7163e231a24129877d38
cp Cargo.lock /tmp/zentinel-rule-body-engine/Cargo.lock
python3 verify.py /tmp/zentinel-rule-body-engine /tmp/zentinel-rule-body-results
```
