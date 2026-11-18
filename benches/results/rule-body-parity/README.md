# Rule and body behavior on Coraza 3.8.1

Engine `ce3b0fc` matched the pinned Go reference on all 4,673 CRS 4.25.0 fixture outcomes with both detector backends. Each build matched all 22 blocking traces and preserved 24 complete connector audit records. The separate native corpus reproduced every baseline stage outcome. [CRS qualification](qualification-before-recursive.json)

The public API comparisons cover transaction-local body limits, scalar and collection macros, named datasets, path arguments, action updates, national identifiers, processor selection and multipart temporary files. The 48 request and response body-limit cases compare bytes consumed, storage errors, overflow flags and intervention status. Rust rejects negative HTTP status codes. Both engines remove temporary uploaded files at transaction close. Rust creates named files only when a policy reads their paths. [Public API results](qualification-intermediate.json)

The schema checks use benign array and object documents with valid and invalid leaves. Before heap-backed validation, nine valid deep inputs produced violations. The intermediate heap validator matched all 48 pinned Go cases, accepted 10,000 nested arrays and rejected 10,001 on a 1 MiB worker stack. The additional scoped fixtures exercise stricter rules that reuse the same recursive schema. [Before](recursive/before-ce3b0fc/receipt.json) · [After](recursive/intermediate.json) · [Scoped Go results](scoped/go-results.txt)

The preliminary full CRS timing used the fork before the recursive validator, source `ce3b0fc`, and baseline `14eb6a0`. [Eight paired runs](pilot/summary.json)
