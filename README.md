<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">ModSecurity engine in Rust</h3>

<p align="center">A pure Rust ModSecurity (SecLang) rule engine that runs the OWASP Core Rule Set, for Rust applications that want a WAF without libmodsecurity.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-modsec/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-modsec/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
</p>

<p align="center">
  <a href="https://docs.rs/zentinel-modsec">API reference</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

`zentinel-modsec` parses ModSecurity `.conf` rule files and evaluates them
against requests and responses. The default build has no C or C++ dependency
and no FFI (`#![deny(unsafe_code)]`). SQL injection and XSS detection
(`@detectSQLi`, `@detectXSS`) use the Rust port of libinjection by default. The optional
`libinjection-ffi` feature selects upstream C libinjection. CI checks individual CRS regression stages on both backends for pull requests and pushes to `main`.
See [CRS conformance](#crs-conformance).

It is the engine behind Zentinel's
[ZentinelSec agent](https://registry.zentinelproxy.io/zentinelsec/). The
[ModSecurity agent](https://github.com/zentinelproxy/zentinel-agent-modsec) is
a different thing: it wraps the C++ libmodsecurity.

### Optional upstream libinjection

Enable `libinjection-ffi` to use upstream C libinjection v4.0.2 for
`@detectSQLi`, `@detectXSS`, and the root `libinjection` API:

```sh
cargo build --features libinjection-ffi
```

This feature requires a C compiler, compiles the vendored BSD-3-Clause source
locally, and adds no Go runtime or dynamic library dependency. The default
remains pure Rust. The original Rust heuristic backend is also always available
explicitly through `libinjection::sqli` and `libinjection::xss`; its detection
semantics differ from upstream. Native parser errors are logged and reported
as matches rather than silently allowing the input. Source provenance and the
third-party license are in [vendor/libinjection](vendor/libinjection/README.md).

The default backend uses `barbacane-libinjection` 0.1.3 and returns upstream-style
SQL fingerprints and the `XSS` label for HTML matches. To compare both
implementations on the v4.0.2 upstream data files, point `LIBINJECTION_DATA_DIR`
at the upstream checkout’s `data` directory and run
`cargo test --release --features libinjection-ffi --test libinjection_conformance upstream_dataset -- --ignored`.

To compare per-call cost, run
`cargo run --release --features libinjection-ffi --example libinjection_cost`.
The example reports raw FFI, the selected API including result conversion,
the Rust port, and the original heuristic. A standalone native C control is provided in
`examples/libinjection_native_cost.c`; compile with `cc -O3 -Ivendor/libinjection
examples/libinjection_native_cost.c vendor/libinjection/libinjection_sqli.c
vendor/libinjection/libinjection_xss.c vendor/libinjection/libinjection_html5.c
-o /tmp/libinjection-native-cost`. Alternate repeated runs on a quiet host:
subtracting raw FFI and native C timings estimates crossing overhead but is
sensitive to scheduling and clock noise.

## Quick start

```toml
[dependencies]
zentinel-modsec = "0.6"
```

```rust
use zentinel_modsec::ModSecurity;

fn main() -> zentinel_modsec::Result<()> {
    // Compile rules once; reuse the engine for every request.
    let modsec = ModSecurity::from_string(r#"
        SecRuleEngine On
        SecRule REQUEST_URI "@contains /admin" \
            "id:1,phase:1,deny,status:403,msg:'Admin access blocked'"
    "#)?;

    let mut tx = modsec.new_transaction();
    tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1")?;
    tx.add_request_header("Host", "example.com")?;
    tx.process_request_headers()?; // runs phase 1

    if let Some(i) = tx.intervention() {
        println!("blocked: status={}, rules={:?}", i.status, i.rule_ids);
    }
    Ok(())
}
```

## Install

As a library, from crates.io: `cargo add zentinel-modsec`.

The crate also builds a small CLI for checking rule files:

```bash
cargo install zentinel-modsec

zentinel-modsec check -r rules.conf                 # parse, print the rule count
zentinel-modsec dump  -r rules.conf                 # list rule IDs by phase
zentinel-modsec test  -r rules.conf -u "/search?q=' OR 1=1--" -b ''
```

`test` runs phase 2 only when a body is given, so pass `-b ''` to evaluate
phase-2 rules (which is where most CRS rules live) on a request without a body.

## Usage

### Phases

Each `process_*` call runs one ModSecurity phase. Rules marked `phase:2` (all
argument and body rules, including the CRS SQLi and XSS rules) only run when
you call `process_request_body()`, even for a `GET` with no body:

```rust
let modsec = ModSecurity::from_string(r#"
    SecRuleEngine On
    SecRule ARGS "@detectSQLi" \
        "id:942100,phase:2,deny,status:403,msg:'SQL injection'"
"#)?;

let mut tx = modsec.new_transaction();
tx.process_uri("/search?q=' OR 1=1--", "GET", "HTTP/1.1")?;
tx.process_request_headers()?; // phase 1: no intervention yet
tx.process_request_body()?;    // phase 2: the rule runs here
assert!(tx.has_intervention());
```

Request and response body access default to Off, matching Coraza. Enable
`SecRequestBodyAccess On` for request inspection. For response inspection also
set `SecResponseBodyAccess On` and an explicit `SecResponseBodyMimeType` list;
the bare MIME list is empty. Run header callbacks before feeding body chunks
when possible, then finish with the corresponding body callback.

`write_request_body()` and `write_response_body()` report how many bytes were
retained for inspection. The caller still owns and forwards its original
input. The `append_*` compatibility wrappers discard that count; all callers
must check `intervention()` after writes. Writes are bounded before allocation.
Request and response limits default to 134217728 and 524288 bytes, respectively;
their actions default to Reject and ProcessPartial. Reaching a limit exactly
also triggers its action. Reject does not copy the offending chunk and sets
status 413 for requests or 500 for responses. ProcessPartial inspects only the
prefix and sets `INBOUND_DATA_ERROR` or `OUTBOUND_DATA_ERROR`; it does not inspect
the remaining tail. DetectionOnly uses ProcessPartial without interruption.

A pre-header write retains at most a provisional prefix. Header `ctl` policy
then resolves access and the pending limit decision; no body phase runs early.
Each header/body phase executes at most once; failed callbacks remain errors
on retries. After a body callback seals an ordinary body,
new bytes produce a visible error; tails after a limit consume zero bytes.
`status` applies to deny/block and drop actions. Redirects accept status
301, 302, 303 or 307 and otherwise use 302, matching Coraza. A drop has
`drop_connection=true` and status zero by default; check the intervention itself,
not only a nonzero HTTP status. Status arguments retain the public `u16` domain.

Response headers can be supplied with `process_response_headers_with_status()`;
`process_response_body()` runs phase 4 after MIME/access checks.
`RESPONSE_CONTENT_LENGTH` holds the inspected byte count starting in phase 4,
including zero for an inspected empty body and the retained prefix length for
`ProcessPartial`. It stays empty when inspection is skipped.

### Detection only and anomaly scoring

Under `SecRuleEngine DetectionOnly` rules match but never intervene;
`tx.matched_rules()` lists what matched. `setvar` on `TX` works as in CRS, and
`tx.anomaly_score()` reads `TX:anomaly_score`. CRS versions with per-paranoia
scores compute separate aggregates; read `TX:blocking_inbound_anomaly_score`
through `tx.tx()` for the score used by inbound blocking. Rules own these
variables, and phase completion preserves their values:

```rust
let modsec = ModSecurity::from_string(r#"
    SecRuleEngine On
    SecRule REQUEST_URI "@contains /admin" \
        "id:1,phase:1,pass,setvar:'TX.anomaly_score=+5'"
    SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \
        "id:2,phase:1,pass,setvar:'TX.anomaly_score=+10'"
    SecRule TX:anomaly_score "@ge 10" \
        "id:100,phase:1,deny,status:403,msg:'Anomaly score exceeded'"
"#)?;
// a request to /admin with User-Agent sqlmap/1.0 scores 15 and is denied
```

### Loading the OWASP CRS

```bash
git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs
cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
cat > /etc/modsecurity/main.conf <<'EOF'
SecRequestBodyAccess On
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/rules/*.conf
EOF
```

```rust
let modsec = zentinel_modsec::ModSecurity::from_file("/etc/modsecurity/main.conf")?;
println!("loaded {} rules", modsec.rule_count());
```

`ModSecurity` is `Send + Sync`: build it once, share it behind an `Arc`, and
create one `Transaction` per request. The API is synchronous, so it can be
called from any async runtime. A minimal Axum middleware:

```rust
async fn waf(
    State(modsec): State<Arc<ModSecurity>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let mut tx = modsec.new_transaction();
    let uri = request.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    tx.process_uri(uri, request.method().as_str(), "HTTP/1.1")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for (name, value) in request.headers() {
        tx.add_request_header_bytes(name.as_str().as_bytes(), value.as_bytes())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    tx.process_request_headers().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Phase 2 (arguments; add the body first if you inspect bodies).
    tx.process_request_body().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(i) = tx.intervention() {
        return Err(StatusCode::from_u16(i.status).unwrap_or(StatusCode::FORBIDDEN));
    }
    Ok(next.run(request).await)
}
```

## What is supported

**Directives:** `SecRule`, `SecAction`, `SecMarker`, `SecRuleEngine`,
`SecDefaultAction`, `SecRuleRemoveById`, `SecRuleUpdateTargetById`,
`SecRuleUpdateTargetByTag`, `Include`.
Body directives are implemented: `SecRequestBodyAccess`, `SecResponseBodyAccess`,
`SecRequestBodyLimit`, `SecResponseBodyLimit`, their `LimitAction` settings,
`SecResponseBodyMimeType` and `SecResponseBodyMimeTypesClear`. Limits must be
between 1 byte and 1 GiB. MIME directives replace the list, matching the pinned
reference implementation. In-memory spooling and no-files limits remain
unsupported and warn; the hard body limit still bounds retained bytes.
`SecRuleUpdateActionById` remains unsupported, with affected rule IDs in its
load-time warning. Other unknown directives also warn
at load. `SecComponentSignature` is accepted as metadata.

`SecRuleUpdateTargetByTag attack-sqli "!ARGS:password"` excludes that argument
from every rule carrying the exact, case-sensitive `attack-sqli` tag. Positive
targets append to the rule; a third argument replaces an existing target, as
with `SecRuleUpdateTargetById`. For a conditional transaction-local exclusion,
use `ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:password` on an earlier rule.
Runtime exclusions also apply to children of a tagged chain starter. Both
forms support regex collection keys such as `ARGS:/^token_/` (the runtime
regex-key behavior follows Coraza 3.8.1). Invalid configure-time targets fail
loading; malformed runtime controls produce load-time warnings with rule IDs.

`ctl:ruleRemoveByTag=TAG` suppresses subsequent rules bearing the exact,
case-sensitive tag for this transaction, including later phases. A tagged
chain starter selects its entire chain. Untagged rules continue to execute.

**Operators:** `@rx`, `@pm`, `@pmFromFile`, `@contains`, `@containsWord`, `@beginsWith`,
`@endsWith`, `@within`, `@streq`, `@eq`, `@ne`, `@gt`, `@ge`, `@lt`, `@le`,
`@detectSQLi`, `@detectXSS`, `@ipMatch`, `@ipMatchFromFile`,
`@validateUrlEncoding`, `@validateUtf8Encoding`, `@validateByteRange`,
`@unconditionalMatch`, `@noMatch`. The file-backed aliases `@pmf` and
`@ipMatchF` read the same files as `@pmFromFile` and `@ipMatchFromFile`.
With `capture`, phrase matches populate `TX:0` through `TX:9` in input order
using the original bytes. If phrases overlap, each capture takes the longest phrase at
the next matching start, including starts inside an earlier match.

`@containsWord` follows ModSecurity v3. It matches case-sensitive bytes bounded
by the input edges or bytes outside ASCII A–Z and a–z. An empty operand matches
every value. Coraza 3.8.1 does not implement this operator. `@strmatch` uses
substring matching and emits a load-time compatibility warning.

`@validateByteRange` accepts decimal bytes and inclusive ranges, for example
`9,13,32-126`. Rules with an invalid static entry fail at load. A macro-supplied
list is checked after expansion. An omitted range matches every input, including
an empty value. A descending range contributes no permitted bytes.

These parse but **never match**: `@verifyCC`, `@verifySSN`, `@verifyCPF`,
`@validateHash`, `@validateDTD`, `@validateSchema`, `@rbl`, `@geoLookup`,
`@gsbLookup`, `@inspectFile`, `@fuzzyHash`, `@rsub`. A rule that depends on one
of them cannot perform the requested check; negating a placeholder can make
it match. These operators produce load-time warnings with rule IDs.

**Transformations:** `lowercase`, `uppercase`, `urlDecode`, `urlDecodeUni`,
`urlEncode`, `base64Decode`, `base64DecodeExt`, `base64Encode`, `hexDecode`,
`hexEncode`, `sqlHexDecode`, `htmlEntityDecode`, `jsDecode`, `cssDecode`,
`escapeSeqDecode`, `utf8toUnicode`, `removeWhitespace`, `compressWhitespace`,
`removeNulls`, `replaceNulls`, `trim`, `trimLeft`, `trimRight`,
`normalizePath`, `normalizePathWin`, `removeComments`, `removeCommentsChar`,
`replaceComments`, `cmdLine`, `md5`, `sha1`, `sha256`, `length`, `none`.
The three parity transformations are placeholders and warn with affected IDs.

Multipart fields, names and filenames retain their original bytes. The parser
honors quoted parameters and extended filenames, preserves repeated parts, and
reports malformed framing/header/parameter states through
`MULTIPART_STRICT_ERROR`. Quoted-printable transfer encoding is decoded before
inspection; other transfer encodings stay raw, as in Coraza's NextPart API. `FILES_SIZES` is keyed by filename;
`FILES_COMBINED_SIZE` counts all multipart payload bytes (files and fields),
excluding MIME framing, matching Coraza. Intentional `ProcessPartial` prefixes
suppress only the EOF strict error, while other malformed states remain visible.

**Body processors:** URL-encoded forms, multipart (including
`MULTIPART_PART_HEADERS`), JSON, XML and explicit RAW. Missing or unknown body
types remain unprocessed unless `ctl:forceRequestBodyVariable=On` selects the
URLENCODED fallback used by Coraza 3.8.1. RAW exposes the body without form
argument extraction. Only RAW and URLENCODED populate `REQUEST_BODY` and its
length; structured processors leave these scalar values empty and zero.

The JSON processor preserves numeric token spelling and duplicate member values.
It exposes each nonempty array's length at the array path alongside its indexed
elements. Completed fields remain available when the processor reports an error.
Flattened keys and values share a byte budget of eight times the acquired JSON
size, with a 4 KiB minimum. The processor allows 64 container levels, 4,096
scalar values and 4,096 array lengths. Exceeding a limit sets `REQBODY_ERROR`.

XML values are stored separately from HTTP arguments. `XML:/*` selects text
tokens and `XML://@*` selects attribute values, including namespace values.
Element and attribute names do not become argument names. Streaming extraction
handles empty elements, text split around entities, CDATA and truncated input
without discarding text already inspected. The predefined XML and reference
HTML4 entities are decoded, without using DTD definitions or resolving external
resources. Suppressed custom entities remain literal and set `REQBODY_ERROR`;
this deliberately retains stronger hidden-content reporting than Coraza's
permissive parser. Bounds on depth and extracted values also report errors.
General XPath is unsupported and produces load-time warnings with rule IDs.

Unsupported variables, including `UNIQUE_ID`, are
reported at load even when a rule also selects implemented variables. Invalid
selector/exclusion regexes and unsupported macro sources also warn with IDs.
Only TX writes are implemented; non-TX `setvar` collection names are ignored
and their writes reach TX, which is reported at load.

`multiMatch` evaluates the original value and each changed transformation stage.
The byte APIs preserve binary input, captures and macro expansions; string APIs
provide display values. Header lookup ignores ASCII case while match metadata
preserves each original header name.

With `SecRuleEngine On`, `allow:phase` ends the current phase and
`allow:request` skips the remaining request rules. Response and logging
rules still run after `allow:request`. Global `allow` skips all remaining
rules, including logging rules, matching Coraza 3.8.1. In `DetectionOnly`,
all three actions record the match and rule evaluation continues.

Accepted action limitations are also reported with rule IDs:
persistent-collection actions, script execution, response modification,
`proxy`, `pause`, `xmlns`, and logging/sanitization policy.
The engine has no log sink; embedding applications must implement logging
policy. Known unsupported controls warn at load without repeating the warning
on each request.

Connectors can enable `Transaction::set_record_rule_messages(true)` and read
`rule_messages()` for expanded `msg` and `logdata` bytes captured at match time.
Recording is disabled by default. The connector applies logging policy and
escapes these bytes for its output format. Supply actual response metadata via
`process_response_headers_with_status` before processing its body.

## CRS conformance

The native runner checks the rule IDs listed in each regression stage under
`tests/regression/tests` of CRS commit `30cb436` (4.31.0-dev). It reads 327
YAML files, including one comment-only file. Of the 5,263 stages, 5,187 have
structured input and rule-ID expectations. The other 76 use encoded requests
or have no rule-ID assertion.

On this pin both the default Rust port and `libinjection-ffi` pass the same
5,096 of 5,187 executed stages. CI checks each backend against the shared manifest.
[The reviewed outcome manifest](tests/fixtures/crs-native-outcomes.tsv)
records each stage by file, test ID and stage number. A changed outcome,
missing or new stage, fixture error, or incomplete engine callback fails CI.
Set `CRS_STAGE_REPORT` to a new file path to save all observed outcomes.

```bash
mkdir -p test-rules
git clone https://github.com/coreruleset/coreruleset.git test-rules/crs
git -C test-rules/crs checkout 30cb436
cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf
cargo test --release --test crs_conformance -- --nocapture
cargo test --release --features libinjection-ffi --test crs_conformance -- --nocapture
```

### Detection and blocking coverage

The corpus runs in the configuration CRS documents for it: `DetectionOnly` at
paranoia level 4. In that mode `block` never blocks, the paranoia gates never
fire, and the anomaly score never reaches rule 949110. It measures whether
individual rules **match**, not whether the WAF **decides** correctly.

That distinction is not academic. A set of defects that made a stock CRS
deployment deny every request, `GET /` included
([#29](https://github.com/zentinelproxy/zentinel-modsec/issues/29)), moved
this number by 23 cases, because none of the machinery they broke runs in this
configuration. `stock_crs_blocks_attacks_and_passes_ordinary_traffic` in the
same file covers the other half: real blocking mode, default paranoia,
asserting the decision for ordinary requests and for attacks. Neither
substitutes for the other.

| | corpus |
|---|---|
| Before the 2026 evaluation fixes | 4,080 |
| Stock CRS evaluation: `skipAfter` in phase 2+, `TX` key case, `block` semantics, `REQUEST_LINE` ([#29](https://github.com/zentinelproxy/zentinel-modsec/issues/29)) | 4,103 |
| `+` decoded as a space in form arguments ([#34](https://github.com/zentinelproxy/zentinel-modsec/issues/34)) | 4,228 |
| Form parameter with no `=` kept rather than dropped ([#38](https://github.com/zentinelproxy/zentinel-modsec/issues/38)) | 4,541 |
| `t:cmdLine` completed ([#31](https://github.com/zentinelproxy/zentinel-modsec/issues/31)) | 4,608 |
| Later fixes, 0.5.0 (`setvar`/`t:`/`ctl:` accumulate, CRLF rule files) | 4,806 |
| Every chain link's `setvar` runs, captures fill `TX:0`..`TX:9`, collections iterate in insertion order, 0.6.0 ([#52](https://github.com/zentinelproxy/zentinel-modsec/pull/52), [#55](https://github.com/zentinelproxy/zentinel-modsec/pull/55)) | 4,900 |

Two of those were bypasses: the `+` encoding and the missing `=` each let a
payload reach the application while the engine inspected nothing.

## Performance

Measured with criterion in `benches/libmodsec_compare.rs`: both engines run the
same ruleset through request phases 1 and 2, single thread, on an Apple
M-series machine. Absolute numbers depend on hardware; the ratios are the
point.

| Benchmark | zentinel-modsec | libmodsecurity 3 (C++) |
|---|---|---|
| Clean request | 1.34 µs | 5.65 µs |
| SQLi detection | 1.40 µs | 16.03 µs |
| Body processing | 1.45 µs | 12.91 µs |
| Rule parsing (complex) | 2.73 µs | 10.58 µs |

Reproduce with `cargo bench --features libmodsec-compare` (needs
libmodsecurity installed); `cargo bench` alone runs the engine's own benches.
An earlier version of this table claimed 10-30x; that benchmark never reached
the phase-2 detection rule on either engine
([#15](https://github.com/zentinelproxy/zentinel-modsec/issues/15)). These
figures are the re-measurement after #15, #17 and #18.

## Development

```bash
cargo build
SKIP_CRS_CONFORMANCE=1 cargo test --all-targets   # unit and integration tests
cargo test --release --test crs_conformance        # needs test-rules/crs, see above
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

Minimum Rust: 1.94.1 (`rust-version` in `Cargo.toml`).

## Related

- [ZentinelSec agent](https://registry.zentinelproxy.io/zentinelsec/): the Zentinel agent built on this engine
- [OWASP CRS](https://coreruleset.org)
- [libmodsecurity](https://github.com/owasp-modsecurity/ModSecurity): the reference C++ implementation

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
