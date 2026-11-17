# Vendored libinjection

Upstream: https://github.com/libinjection/libinjection
Release: v4.0.2
Commit: 7244a1e3c633ea13b3c89d2f670da25789e152fc
License: BSD-3-Clause, reproduced in COPYING.

Only the unchanged C implementation and headers are vendored. The
`libinjection-ffi` Cargo feature compiles them locally; builds never fetch source.
v4 returns parser errors rather than aborting the embedding process.
