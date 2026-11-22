# Changelog

Notable changes to `zentinel-modsec`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/).

CRS figures are passing cases of the regression corpus at the CRS commit CI
pins (see [`docs/conformance.md`](docs/conformance.md)).

## [Unreleased]

CRS conformance: 4,975 to 4,978 of 5,184 runnable cases.

### Behavior changes

- **An intervention's `msg` and `logdata` have their macros expanded** at
  the match, as ModSecurity logs them: `Inbound Anomaly Score Exceeded (Total
  Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE})` reads with its score.
  `nolog` is recorded (`RuleMetadata::nolog`). (#108)

- **`t:normalizePath`, `t:normalizePathWin` and `t:escapeSeqDecode` are
  libmodsecurity v3's** (`normalise_path.cc`, `escape_seq_decode.cc`), ported
  step for step on bytes:
  - A relative path keeps the back-references it cannot resolve:
    `../.history` stays as it is, where it lost its `../`.
  - A path ending on a back-reference is normalized as v3 leaves it:
    `/a/b/..` is `/a`, and `/foo/..` and `a/..` are empty.
  - Only `normalizePathWin` treats a backslash as a separator;
    `normalizePath` leaves `a\b\c` as it is.
  - `escapeSeqDecode` decodes `\a \b \f \n \r \t \v \\ \? \' \"`, `\xHH` and
    up to three octal digits; any other escaped byte becomes that byte, its
    backslash dropped; a lone trailing backslash stays. `\u` is not an
    escape there, as in v3. (#106)

### Added

- A key selection whose regular expression does not compile is reported at
  load, naming the rule and the expression: a rule's target (`ARGS:/bad(/`,
  which then inspects nothing) or exclusion (`!ARGS:/bad(/`, which then leaves
  nothing out), a `SecRuleUpdateTargetById` target, or a
  `ctl:ruleRemoveTargetById` / `ctl:ruleRemoveTargetByTag` target (once per
  distinct directive). It still matches no key, as in ModSecurity v3.
  `KeyRegex::error` gives the reason. (#115)

- `Transaction::messages()`: a `RuleMessage` for each matched rule that logs
  (every rule but a `nolog` one, as v3's `m_saveMessage`), with its id, `rev`,
  `msg`, `logdata`, severity, `ver`, maturity, accuracy and tags, its macros
  expanded at the match. `RuleMessage::log_line()` renders it as v3's
  `RuleMessage::_details` does (`rule_message.cc`): `msg` as written, `data`
  cut at 200 bytes (`limitTo`) and, with `rev`, `ver` and the tags, escaped
  by `toHexIfNeeded` with `"` and `\` as `\xHH`; then the line through
  `toHexIfNeeded` as `RuleMessage::log` does. The file, line, hostname, URI,
  unique id and reference fields are the embedding application's. (#108)

- `Transaction::request_body_error()`: `REQBODY_ERROR_MSG`. (#108)

- `Transaction::set_response_status(status, protocol)`: `RESPONSE_STATUS` and
  `RESPONSE_PROTOCOL`, for an application that runs the response phases.
  (#108)

### Performance

- Evaluating a rule no longer copies the values of its targets into one list
  before testing them. Each target's values are tested from the list the
  resolver returned, which removes an allocation, its regrowth and a copy of
  every value for each rule evaluated. (#111)

### API changes

- `CompiledRule` gains a public `metadata` field (what a match reports,
  prepared at load), which breaks code that builds one with a struct literal.
  (#108)

- `RuleMetadata` gains a public `nolog` field. (#108)

## [0.11.0] - 2026-11-22

CRS conformance: 4,969 to 4,975 of 5,184 runnable cases.

### Behavior changes

- **`multiMatch` runs the operator at every stage of the transformation
  pipeline**, as ModSecurity does: on the value before any transformation and
  after each transformation that changed it. It was parsed and ignored, so the
  operator saw only the last stage. CRS 930110 finds `..\` before `t:cmdLine`
  removes the backslash, and 934100 finds `new Function (` before
  `t:base64Decode` turns it into bytes. The flag is
  collected at load (`CompiledRule::multi_match`, a new public field).

- **`@detectXSS` gives libinjection's verdict.** It used to be a set of
  regular expressions and keyword lists. Those flagged text that libinjection
  clears, such as `online=1`, `javascript:alert(1)` without a tag, or
  `document.cookie`, and missed what libinjection flags, such as
  `<div style=...>`, `<!DOCTYPE`, `xmlns:` attributes or `<x:script>`. It is
  now a port of libinjection v4.0.2's XSS detector and the HTML5 tokenizer it
  runs on, so the verdict matches C libinjection. Some inputs that matched
  before no longer do, and some that did not now do. A match reports the whole
  input (`TX:0` with `capture`), as ModSecurity v3 does, rather than a label.
  CRS 941100 tests 2 and 3 now pass. (#105)

### Performance

- `@detectXSS` takes about a third of the time per call on a mixed corpus of
  CRS payloads, libinjection test data and ordinary values (about 230 ns
  against 660 ns). Input with neither `<` nor `=` cannot be XSS for
  libinjection and returns at once. (#105)

- A transformation no longer runs on a value it cannot change. `lowercase`
  built a lowercased copy and `urlDecodeUni`, `jsDecode`, `cssDecode`,
  `cmdLine` and others rebuilt the value character by character, then found
  the result equal and dropped it. Each now first scans for the bytes it
  reacts to (`%`, `\`, `&`, an uppercase letter, ...) and the pipeline skips
  it when there are none. (#110)

### API changes

- `Transformation` gains `leaves_unchanged`, the scan described above. It has
  a default that returns `false`, so an existing implementation compiles and
  runs as before. (#110)

### Fixed

- **An operator argument with a macro that does not compile after expansion
  no longer ends the phase.** `@rx %{request_headers.x}` with a value that is
  not a valid pattern returned an error, and the rules after it in the phase
  did not run. As in ModSecurity v3 (`operators/rx.cc`), it is now neither a
  match nor a mismatch: the rule does not fire, negated or not, and evaluation
  continues.
- **`!@rx %{...}` keeps its negation.** The argument was also compiled once as
  written at load; `%{...}` is often not a valid pattern, so the rule was
  treated like an invalid fixed pattern, which drops the negation and logs an
  error. The expanded pattern then ran without it. Arguments with a macro are
  no longer judged at load.

## [0.10.0] - 2026-11-21

### Behavior changes

- **Regex key selections fold ASCII only and match keys as bytes**, as
  ModSecurity v3 compiles them (PCRE caseless, without UTF): `!ARGS:/^session/`
  still leaves `SESSION`, and no longer leaves `ſession` (U+017F). `\w`, `\d`
  and `.` are ASCII and single bytes there too.

### Performance

- A regex selection or exclusion (`ARGS:/^user/`, `!REQUEST_COOKIES:/__utm/`)
  is compiled once, as the rule is read, and one compiled program serves every
  rule and thread naming it. `cached_regex` handed out a clone per use, and a
  cloned `Regex` starts with an empty cache pool, so each match allocated the
  matcher's scratch space again: once per cookie for each CRS rule excluding
  `/__utm/`, and once per argument for each regex exclusion.

- What a match does (`setvar`, `ctl:`, flow and disruptive action) is
  worked out per rule at load and read in place, and a `setvar` no longer
  copies its collection, name and operation before it is applied. (#103)

### API changes

- `Selection::Regex` holds a `KeyRegex` (compiled), not the pattern text;
  `KeyRegex::as_str` gives the text.
- `VariableSpec::exclusions` is a `Vec<TargetExclusion>` (parsed), not
  `Vec<String>`; `TargetExclusion::text` gives the text.
- `Collection::get_regex`, `HashMapCollection::iter_regex` and
  `TxCollection::iter_regex` take a `&KeyRegex`.
- `CompiledRule` gains a public `on_match` field (the prepared result of its
  actions), which breaks code that builds one with a struct literal. (#103)

## [0.9.0] - 2026-11-21

No change to what rules match. `CompiledRule` gains two public fields
(`tags`, `skip_after_index`), which breaks code that builds one with a struct
literal; hence the minor version.

### Performance

- Rule targets and `%{...}` macros read collections in place:
  `HashMapCollection` and `TxCollection` gain `iter`, `values` and
  `iter_regex`, which hand out what `all`, `get` and `get_regex` used to
  collect into a list first. (#98)
- A rule's tags and the position its `skipAfter` resumes at are prepared
  at load, so `ctl:ruleRemoveTargetByTag` no longer scans the actions of
  every later rule and a jump no longer looks its marker up by name. (#100)

## [0.8.1] - 2026-11-21

A security fix: with the OWASP CRS at blocking paranoia level 3, attacks were
not blocked. Upgrade if you run level 3; levels 1, 2 and 4 are not affected.

### Fixed

- **`skipAfter` to a marker directly after the rule skips nothing.** It used
  to skip the rest of the phase, as for a marker that is not ahead. CRS rule
  files end with their paranoia-level gates directly before the file's end
  marker, and at paranoia level 3 those gates fire in the files without
  level-4 rules, so from `REQUEST-911` on nothing was evaluated, including
  the blocking evaluation: a level-3 deployment did not block. Levels 1, 2
  and 4 were not affected. (#97)

## [0.8.0] - 2026-11-21

CRS conformance: 4,949 to 4,969 of 5,184 runnable cases.

### Behavior changes

- **Regex key selections compare keys case-insensitively**, as in ModSecurity
  v3: `ARGS:/^user/`, `TX:/.../` and `!ARGS:/.../` now match keys in any
  case. CRS 922110 now sees the multipart Content-Type keys 922150 sets. Unlike
  v3, which folds ASCII only, non-ASCII letters fold too. (#83, by PQCrypta)

- **`@detectSQLi` gives libinjection's verdict.** It used to be a set of
  regular expressions and a small fingerprint list, which matched ordinary
  crawler User-Agents (AhrefsBot, PetalBot, `meta-externalagent`, ...) under
  CRS 942100 and missed some injections. It is now a port of libinjection
  v4.0.2's SQLi detector: the same tokenizer, folding, fingerprint list and
  false-positive filter, so the verdict and the reported fingerprint (`TX:0`)
  match C libinjection. Some inputs that matched before no longer do, and some
  that did not now do. (#84)
- **Rules after a form feed, vertical tab or Unicode space are loaded.** Any
  whitespace character other than space, tab or carriage return between
  directives used to end the configuration silently, dropping every directive
  after it. Those characters now separate tokens, and U+0085, U+2028 and
  U+2029 end a line or a comment. v3 accepts none of them, so the load logs
  one warning per distinct character with its position. Content that used to
  be dropped is now parsed, so an error in it surfaces at load. (#79)
- **An unquoted argument keeps a leading backslash.** `SecRule REQUEST_URI
  \.php$` compiled `.php$` and now compiles `\.php$`; `Include
  \\server\share\rules.conf` and `SecMarker \name` keep theirs too. A stray
  backslash outside a word is still ignored, now with a warning. (#79)
- **A numeric operator with a bare macro name never matches.** `@gt
  %{REMOTE_PORT}` was expanded as `tx.REMOTE_PORT` and compared against 0. v3
  reads a bare name as the variable, which the engine cannot resolve in an
  operand, so `@eq`, `@gt`, `@lt`, `@ge` and `@le` with a bare name other than
  `MATCHED_VAR` or `MATCHED_VAR_NAME` are handled like a macro on an
  unresolvable collection: no match, and one load warning per macro. Other
  operators and `setvar` still read a bare name from TX. (#87)

### Performance

- `@rx` answers a value that does not match without allocating capture
  slots. (#91)
- A rule's message, tags and other metadata are collected when it
  intervenes, not copied on every match. (#92)
- `%{...}` macros in operands and `setvar` are expanded without running a
  regex, and whether an operand holds one is decided at load. (#93)
- Rule targets are resolved without copying each variable's name and
  value; a name is rendered only for a value that matches. (#94)

## [0.7.0] - 2026-11-21

CRS conformance: 4,900 to 4,949 of 5,184 runnable cases.

### Behavior changes

Changes that alter what loads or what rules match. Read these before
upgrading.

- **A missing literal `Include` is a load error.** It used to be skipped
  silently. A glob with no matches is still allowed. A relative path is now
  tried as given (relative to the working directory) first and beside the
  declaring file second, as in ModSecurity v3; 0.6.0 tried the other order, so
  a config where both files exist can now load the other one. The limit of 100
  `Include` directives is replaced by a nesting limit of 100 levels, and a file
  that includes itself is reported as a cycle. A glob match that cannot be
  inspected, such as a dangling symlink, is skipped with a warning.
  Configuration includes load atomically: a failed load leaves the previous
  configuration in place. (#76)
- **`SecRuleRemoveByTag` and `SecRuleRemoveByMsg` are supported.** They were
  previously logged and skipped, so the rules they name ran. Like
  `SecRuleRemoveById`, they apply to the whole ruleset wherever they are
  declared, and remove a chain with its starter. Tags and messages are
  compared exactly against the rule text. (#77)
- **The engine no longer writes TX score variables.** At the end of every
  phase it used to overwrite `tx.anomaly_score` and seven per-category scores
  (`tx.sql_injection_score`, `tx.xss_score`, ...) from an internal tracker, so
  a score a rule set in one phase read 0 in the next, and those variables
  existed even when no rule had set them. TX is now left to the rules, and
  `Transaction::anomaly_score()` reads `TX:anomaly_score`. The public
  `AnomalyScore` type remains but the engine no longer uses it. (#81)
- **Literal TX assignments keep their spelling.** `setvar:tx.code=007` stored
  `7`; it now stores `007`, so a later string comparison sees what the rule
  wrote. (#78)
- **`setvar` into a collection other than TX is skipped, with a warning.**
  Writes to `ip.`, `session.`, `user.`, `global.` or `resource.` used to land in
  TX under the same member name, so `setvar:ip.score=1` overwrote `TX:score`.
  They are now removed when the rules load, with one warning per collection,
  and the rest of the rule still runs. (#78)
- **CRS rules gated on `ctl:ruleRemoveByTag` take effect.** CRS sampling mode
  (901410, 901450) and the 905110 exception for Apache's internal dummy
  connection now work. Embedders must pass the real client address
  (`Transaction::set_client_addr`); a loopback `REMOTE_ADDR` with a matching
  request skips the CRS. 905100 stays inert (see
  [`docs/v3-compatibility.md`](docs/v3-compatibility.md)). (#67)
- **`setvar` arithmetic saturates** at `i64::MIN` and `i64::MAX`. An operand
  outside the range, including one expanded from request data
  (`=+%{tx.1}`), used to panic in builds with overflow checks; it can no
  longer crash a transaction or wrap a score below a blocking threshold. (#82)
- **Numeric operators compare empty and non-numeric operands as 0.** `@eq`,
  `@gt`, `@lt`, `@ge` and `@le` read both sides as v3 does (`atoll`/`stoi`):
  leading whitespace skipped, an optional sign, digits up to the first other
  byte, 0 if there are none. Previously such an operand was a no-match, and a
  negated rule (`!@eq 0`) then matched: the recommended configuration's
  request body checks (200002, 200003) denied requests whose value was empty.
  An argument using a macro on a collection the engine cannot resolve
  (`%{env.MAX_LEN}`) is the exception: the rule never matches, and the load
  logs one warning per macro with the number of rules affected. (#80)
- **`t:urlDecodeUni` folds full-width ASCII escapes** (`%uFF01`..`%uFF5E`) to
  the ASCII characters they stand for, so `%uFF1C` decodes to `<`. Literal
  full-width characters in the input are left as they are. (#71)

### Added

- `ctl:ruleRemoveByTag` and `ctl:ruleRemoveTargetByTag`. Tags match exactly
  and case-sensitively; removals accumulate and affect rules evaluated
  afterwards. (#67)
- `UNIQUE_ID`: each transaction gets a distinct, unpredictable identifier.
  `Transaction::set_unique_id` replaces it with the application's own request
  ID, which must not be client-controlled. (#67)
- `FILES_SIZES` and `FILES_COMBINED_SIZE`, measured in bytes by the multipart
  processor, which now splits the body as bytes. CRS 920410's upload limit is
  enforced. (#67)
- `ctl:forceRequestBodyVariable` is accepted. It has nothing to do:
  `REQUEST_BODY` always holds the raw body. (#67)
- A benchmark of request latency against the full OWASP CRS 4.25.0, with
  setup in `benches/README.md`. (#69)

### Fixed

- `t:normalizePathWin` emits forward slashes, and converts backslashes before
  resolving path components. (#70)
- `t:utf8toUnicode` encodes non-ASCII code points in the IIS `%u` form. (#72)
- Rule IDs in balanced quotes (`id:'942100'`) parse, with the same range checks
  as unquoted IDs. (#73)
- `@ipMatch` matches IPv4-mapped IPv6 addresses against the masked network
  number, for inline and file-based lists. (#74)
- A single-quoted `SecRuleRemoveByTag` or `SecRuleRemoveByMsg` value is
  unquoted, and a trailing `\` followed by a blank line no longer pulls the
  next directive into the value. (#77)
- When an unknown directive is skipped, the line after it is no longer
  swallowed if the directive ends in a comment. (#76)

### Performance

- Phase rules are borrowed from the compiled ruleset instead of copied for
  every request. (#75)
- Multipart bodies are split with `memchr::memmem`. (#67)

## Earlier releases

0.1.2 through 0.6.0 are tagged in Git (`v0.1.2` ... `v0.6.0`); see the tags
and the commit history for what each contains.

[Unreleased]: https://github.com/zentinelproxy/zentinel-modsec/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/zentinelproxy/zentinel-modsec/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/zentinelproxy/zentinel-modsec/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/zentinelproxy/zentinel-modsec/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/zentinelproxy/zentinel-modsec/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/zentinelproxy/zentinel-modsec/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/zentinelproxy/zentinel-modsec/compare/v0.6.0...v0.7.0
