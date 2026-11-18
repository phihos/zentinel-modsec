# Engine refactoring checks

Runtime `af315574` shares collection lookup between SecLang targets and macros, centralizes body limits and phase guards, and separates match actions, rule compilation and recursive schema compilation from request evaluation. The comparison uses runtime `d8402968`, the source at the start of the refactor. Its successor `47a55b6` changed only the handoff. [Source changes](https://github.com/phihos/zentinel-modsec/compare/47a55b6..af315574)

## Behavior

Both the Rust and C detector builds reproduced every case classification from Coraza 3.8.1 on OWASP CRS 4.25.0. Each reported 4,655 passes, 17 failures and one fixture error. Both retained the previous outcome for every native CRS stage, every ordered blocking trace across 22 requests, and every byte in 24 connector audit fixtures. [CRS and blocking results](crs.json) · [Audit comparison](audit.json)

All public rule, body and recursive-schema fixture outputs matched the previous runtime byte for byte, including the two documented Coraza differences in multipart metadata and invalid HTTP status handling. The verifier and dependency lock from the previous qualification also apply to this revision. [Output hashes](public-api.json) · [Fixtures and replay instructions](../rule-body-parity/README.md#replaying-the-public-comparisons)

The Rust build passed 776 tests and the FFI build passed 778. Strict Clippy and documentation builds passed on both. The separately enabled detector test passed against 167,646 corpus inputs. The stock CRS score test and native CRS suite ran with a pinned checkout. [Source verification](source/receipt.json)

## Full CRS request latency

The benchmark loaded all 698 rules, checked a blocking decision and timed allowed GET, form POST and JSON POST requests. Each revision processed 15,360 measured requests per workload in 16 interleaved pairs on two physical cores. Both release workers used the same Rust compiler, dependency lock, driver and rules. [Workload](../rule-body-parity/timing/full_crs.rs) · [Raw pairs on core 14](timing/pairs/receipt.json) · [Raw pairs on core 7](timing/repeat/receipt.json)

| Workload | Median wall time before → after | Median paired wall change | Faster pairs | Median paired thread CPU change |
|---|---:|---:|---:|---:|
| GET | 41.44 → 41.48 µs | −2.24% | 13/16 | −2.15% |
| Form POST | 52.27 → 52.81 µs | −1.37% | 10/16 | −2.21% |
| JSON POST | 62.56 → 61.15 µs | −2.28% | 12/16 | −2.14% |

The time columns summarize each revision across runs. The percentage columns compare adjacent before/after batches under similar host load. Form POST varied most by core. Its paired wall time fell 3.14% on core 14 and rose 1.04% on core 7. [Combined results](timing/comparison.json)

The first refactored build was 5–7% slower across the three workloads. The final build visits collection maps directly, keeps rule evaluation in the phase loop, moves general variable traversal outside that loop and constructs collection availability once per phase. [First comparison](timing/first-candidate.json)
