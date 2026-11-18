//! Pattern matching operators (@rx, @pm).
//!
//! Compiled regexes and phrase automata are shared across live rulesets.

use super::traits::{ByteOperatorResult, Operator, OperatorResult};
use crate::error::{Error, Result};
use aho_corasick::{AhoCorasick, MatchKind};
use once_cell::sync::Lazy;
use regex::bytes::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

/// A cache does not own the regexes: dropping the last rule using a pattern
/// releases its compiled automata and search caches. Stale pattern keys are
/// removed on a miss so repeated configuration reloads cannot accumulate them.
#[derive(Default)]
struct RegexCache {
    entries: Mutex<HashMap<String, Weak<Regex>>>,
}

impl RegexCache {
    fn get(&self, pattern: &str) -> Result<Arc<Regex>> {
        // Compilation is serialized with insertion, preventing concurrent
        // loads of the same pattern from building duplicate automata. Matching
        // never takes this lock.
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let binary = matches_arbitrary_bytes(pattern);
        let key = format!(
            "unicode={};dotall={};multiline={};binary={}:{}",
            !binary, !binary, !binary, binary, pattern
        );
        if let Some(regex) = entries.get(&key).and_then(Weak::upgrade) {
            return Ok(regex);
        }
        entries.retain(|_, regex| regex.strong_count() > 0);
        let regex = Arc::new(
            RegexBuilder::new(&normalize_binary_braced_escapes(pattern, binary))
                .unicode(!binary)
                .dot_matches_new_line(!binary)
                .multi_line(!binary)
                .build()
                .map_err(|source| Error::RegexCompile {
                    pattern: pattern.to_string(),
                    source,
                })?,
        );
        entries.insert(key, Arc::downgrade(&regex));
        Ok(regex)
    }
}

static REGEX_CACHE: Lazy<RegexCache> = Lazy::new(RegexCache::default);

/// Coraza chooses its binary matcher when decoded byte escapes in the
/// expression do not form UTF-8. Preserve this selection instead of treating
/// each high-byte escape as a Unicode code point.
fn matches_arbitrary_bytes(pattern: &str) -> bool {
    let input = pattern.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\\' && i + 3 < input.len() && input[i + 1] == b'x' {
            let (start, end, next) = if input[i + 2] == b'{' {
                match input[i + 3..].iter().position(|&b| b == b'}') {
                    Some(n) => (i + 3, i + 3 + n, i + 4 + n),
                    None => {
                        decoded.push(input[i]);
                        i += 1;
                        continue;
                    }
                }
            } else {
                (i + 2, i + 4, i + 4)
            };
            if let Ok(text) = std::str::from_utf8(&input[start..end]) {
                if let Ok(byte) = u8::from_str_radix(text, 16) {
                    decoded.push(byte);
                    i = next;
                    continue;
                }
            }
        }
        decoded.push(input[i]);
        i += 1;
    }
    std::str::from_utf8(&decoded).is_err()
}

/// Rust's byte grammar accepts `\\xFF`, but rejects the Unicode-escape
/// spelling `\\x{FF}` with Unicode mode disabled. Coraza's binary grammar
/// accepts both for byte values. Normalize only unescaped braced byte escapes;
/// backslash pairs and class/range punctuation retain their original meaning.
fn normalize_binary_braced_escapes(pattern: &str, binary: bool) -> std::borrow::Cow<'_, str> {
    if !binary {
        return std::borrow::Cow::Borrowed(pattern);
    }
    let input = pattern.as_bytes();
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    let mut changed = false;
    while i < input.len() {
        if input[i] == b'\\' && i + 1 < input.len() {
            if input[i + 1] == b'\\' {
                out.extend_from_slice(&input[i..i + 2]);
                i += 2;
                continue;
            }
            if input[i + 1] == b'x' && input.get(i + 2) == Some(&b'{') {
                if let Some(close) = input[i + 3..].iter().position(|&b| b == b'}') {
                    let end = i + 3 + close;
                    if let Ok(hex) = std::str::from_utf8(&input[i + 3..end]) {
                        if let Ok(value) = u8::from_str_radix(hex, 16) {
                            const HEX: &[u8; 16] = b"0123456789abcdef";
                            out.extend_from_slice(&[
                                b'\\',
                                b'x',
                                HEX[usize::from(value >> 4)],
                                HEX[usize::from(value & 15)],
                            ]);
                            i = end + 1;
                            changed = true;
                            continue;
                        }
                    }
                }
            }
            out.extend_from_slice(&input[i..i + 2]);
            i += 2;
            continue;
        }
        out.push(input[i]);
        i += 1;
    }
    if changed {
        std::borrow::Cow::Owned(String::from_utf8(out).expect("only ASCII escapes were replaced"))
    } else {
        std::borrow::Cow::Borrowed(pattern)
    }
}

/// Regex operator (@rx) with process-wide compilation sharing.
///
/// The exact pattern is the cache key, including every inline flag (such as
/// `(?i)` and `(?-u)`). All operators use the same `Regex::new` builder defaults;
/// if external flags or limits are added, those settings must join the key.
/// Compilation happens at load time so an oversized program, like a syntax
/// error, is reported by the loader with the affected rule ID.
pub struct RxOperator {
    compiled: Arc<Regex>,
}

impl RxOperator {
    /// Compile a regex or share the compiled object of an existing live rule.
    pub fn new(pattern: &str) -> Result<Self> {
        if pattern.is_empty() {
            return Err(Error::RegexCompile {
                pattern: pattern.to_string(),
                source: regex::Error::Syntax("empty pattern".to_string()),
            });
        }
        Ok(Self {
            compiled: REGEX_CACHE.get(pattern)?,
        })
    }
}

impl Operator for RxOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        // String callers receive escaped presentations for captures that split
        // a UTF-8 sequence; engine evaluation uses the original bytes below.
        self.execute_bytes(value.as_bytes())
            .expect("regex byte evaluation is infallible")
            .into_text()
    }

    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        self.execute_rule_bytes(value, true)
    }

    fn execute_rule_bytes(&self, value: &[u8], capture: bool) -> Result<ByteOperatorResult> {
        if !capture || self.compiled.captures_len() == 1 {
            return Ok(self
                .compiled
                .find(value)
                .map_or_else(ByteOperatorResult::no_match, |m| {
                    ByteOperatorResult::matched(m.as_bytes())
                }));
        }
        Ok(if let Some(captures) = self.compiled.captures(value) {
            ByteOperatorResult {
                matched: true,
                captures: captures
                    .iter()
                    .skip(1)
                    .map(|capture| capture.map(|m| m.as_bytes().to_vec()).unwrap_or_default())
                    .collect(),
                matched_value: captures.get(0).map(|m| m.as_bytes().to_vec()),
            }
        } else {
            ByteOperatorResult::no_match()
        })
    }

    fn name(&self) -> &'static str {
        "rx"
    }

    fn supports_capture(&self) -> bool {
        true
    }
}

/// Phrase match operator (@pm).
pub struct PmOperator {
    program: Arc<AhoCorasick>,
}

/// Exact parsed phrases, including order and case, identify the program.
/// Paths are deliberately absent: edited files must compile their new content.
/// Weak values release automata with the last live ruleset, like the RX cache.
#[derive(Default)]
struct PhraseCache {
    entries: Mutex<HashMap<Vec<Vec<u8>>, Weak<AhoCorasick>>>,
}

impl PhraseCache {
    fn get(&self, patterns: Vec<Vec<u8>>) -> Result<Arc<AhoCorasick>> {
        // Serialize compilation with insertion so simultaneous configuration
        // loads do not briefly allocate duplicate large automata. Searches
        // access only the immutable program and never lock this cache.
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(program) = entries.get(patterns.as_slice()).and_then(Weak::upgrade) {
            return Ok(program);
        }
        entries.retain(|_, program| program.strong_count() > 0);
        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .map_err(|error| Error::PatternSet {
                message: error.to_string(),
            })?;
        let program = Arc::new(automaton);
        entries.insert(patterns, Arc::downgrade(&program));
        Ok(program)
    }
}

static PHRASE_CACHE: Lazy<PhraseCache> = Lazy::new(PhraseCache::default);

impl PmOperator {
    #[cfg(test)]
    fn automaton_address(&self) -> *const AhoCorasick {
        Arc::as_ptr(&self.program)
    }

    /// Create a new phrase match operator from space-separated patterns.
    pub fn new(patterns_str: &str) -> Result<Self> {
        Self::from_patterns(patterns_str.split_whitespace().map(str::as_bytes))
    }

    pub(super) fn from_patterns<'a>(patterns: impl Iterator<Item = &'a [u8]>) -> Result<Self> {
        let patterns: Vec<_> = patterns.map(<[u8]>::to_vec).collect();
        if patterns.is_empty() {
            return Err(Error::PatternSet {
                message: "empty pattern list".to_string(),
            });
        }

        Ok(Self {
            program: PHRASE_CACHE.get(patterns)?,
        })
    }

    /// Create a phrase match operator from a file.
    pub fn from_file(path: &str) -> Result<Self> {
        let path = std::path::Path::new(path);
        let mut file = std::fs::read_to_string(path);
        // Inline configurations may name a file in the usual CRS directories.
        // A supplied directory or an unreadable file is authoritative.
        if path.parent() == Some(std::path::Path::new("")) {
            for dir in ["test-rules/crs/rules", "rules"] {
                if !matches!(&file, Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
                    break;
                }
                file = std::fs::read_to_string(std::path::Path::new(dir).join(path));
            }
        }
        let content = file.map_err(|source| Error::RuleFileLoad {
            path: path.into(),
            source,
        })?;

        let patterns = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.as_bytes().to_vec())
            .collect();
        // An empty data file is a valid list with no matching phrases.
        Ok(Self {
            program: PHRASE_CACHE.get(patterns)?,
        })
    }
}

impl Operator for PmOperator {
    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        self.execute_rule_bytes(value, true)
    }

    fn execute_rule_bytes(&self, value: &[u8], capture: bool) -> Result<ByteOperatorResult> {
        let Some(first) = self.program.find(value) else {
            return Ok(ByteOperatorResult::no_match());
        };
        let mut result = ByteOperatorResult::matched(&value[first.range()]);
        if capture {
            // Coraza selects the longest phrase at each successive start.
            // A later capture may begin inside the preceding one.
            let mut start = first.start() + 1;
            while result.captures.len() < 9 {
                let input = aho_corasick::Input::new(value).span(start..value.len());
                let Some(next) = self.program.find(input) else {
                    break;
                };
                result.captures.push(value[next.range()].to_vec());
                start = next.start() + 1;
            }
        }
        Ok(result)
    }

    fn execute(&self, value: &str) -> OperatorResult {
        self.execute_bytes(value.as_bytes())
            .expect("infallible phrase search")
            .into_text()
    }

    fn supports_capture(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "pm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rx_simple() {
        let op = RxOperator::new("^admin").unwrap();
        assert!(op.execute("admin").matched);
        assert!(!op.execute("user").matched);
    }

    #[test]
    fn test_rx_captures() {
        let op = RxOperator::new(r"user=(\w+)").unwrap();
        let result = op.execute("user=john");
        assert!(result.matched);
        assert_eq!(result.captures, vec!["john"]);
    }

    #[test]
    fn identical_patterns_share_the_compiled_regex() {
        let first = RxOperator::new(r"(?i:shared-regex)-(\d+)").unwrap();
        let second = RxOperator::new(r"(?i:shared-regex)-(\d+)").unwrap();
        assert!(Arc::ptr_eq(&first.compiled, &second.compiled));
        assert_eq!(second.execute("SHARED-REGEX-42").captures, vec!["42"]);
    }

    #[test]
    fn different_flags_do_not_share_or_change_matching() {
        let sensitive = RxOperator::new("^cache-flags$").unwrap();
        let insensitive = RxOperator::new("(?i)^cache-flags$").unwrap();
        assert!(!Arc::ptr_eq(&sensitive.compiled, &insensitive.compiled));
        assert!(!sensitive.execute("CACHE-FLAGS").matched);
        assert!(insensitive.execute("CACHE-FLAGS").matched);
    }

    #[test]
    fn rulesets_with_different_exclusions_share_regexes() {
        let rules = r#"SecRuleEngine On
SecRule ARGS "@rx ^shared-exclusion-pattern$" "id:1001,phase:2,deny""#;
        let original = crate::ModSecurity::from_string(rules).unwrap();
        let excluded = crate::ModSecurity::from_string(&format!(
            "{rules}\nSecRuleUpdateTargetById 1001 \"!ARGS:skip\""
        ))
        .unwrap();
        let owners = REGEX_CACHE.entries.lock().unwrap()
            ["unicode=true;dotall=true;multiline=true;binary=false:^shared-exclusion-pattern$"]
            .strong_count();
        assert_eq!(owners, 2, "one shared regex owned by both loaded rulesets");
        for (engine, should_block) in [(&original, true), (&excluded, false)] {
            let mut tx = engine.new_transaction();
            tx.process_uri("/?skip=shared-exclusion-pattern", "GET", "HTTP/1.1")
                .unwrap();
            tx.process_request_headers().unwrap();
            tx.process_request_body().unwrap();
            assert_eq!(tx.has_intervention(), should_block);
        }
    }

    #[test]
    fn concurrent_loads_share_a_single_compiled_regex() {
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    RxOperator::new(r"^concurrent-cache-(\w+)$").unwrap()
                })
            })
            .collect();
        let operators: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        for operator in &operators[1..] {
            assert!(Arc::ptr_eq(&operators[0].compiled, &operator.compiled));
        }
    }

    #[test]
    fn dropped_regexes_are_released_and_stale_keys_are_pruned() {
        // A local cache keeps this lifetime assertion independent of other
        // tests running against the process-wide cache concurrently.
        let cache = RegexCache::default();
        let compiled = cache.get("^dropped-cache-pattern$").unwrap();
        let weak = Arc::downgrade(&compiled);
        drop(compiled);
        assert!(weak.upgrade().is_none());
        let live = cache.get("^replacement-cache-pattern$").unwrap();
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(Arc::ptr_eq(
            &live,
            &entries["unicode=true;dotall=true;multiline=true;binary=false:^replacement-cache-pattern$"].upgrade().unwrap()
        ));
    }

    #[test]
    fn program_size_failure_is_reported_at_load_time() {
        // Valid syntax, but the default regex compiler cannot build the
        // expanded Unicode repetitions within its program size limit.
        assert!(RxOperator::new(r"\w{100000}").is_err());
    }

    #[test]
    fn phrase_cache_shares_exact_parsed_content_and_retains_match_portions() {
        let first = PmOperator::new("ADMIN root").unwrap();
        let second = PmOperator::new("  ADMIN\n root  ").unwrap();
        assert_eq!(first.automaton_address(), second.automaton_address());
        let different_case = PmOperator::new("admin root").unwrap();
        assert_ne!(
            first.automaton_address(),
            different_case.automaton_address()
        );
        assert_eq!(
            first.execute_bytes(b"xxadmin\xff").unwrap().matched_value,
            Some(b"admin".to_vec())
        );
        assert_eq!(
            different_case
                .execute_bytes(b"xxadmin\xff")
                .unwrap()
                .matched_value,
            Some(b"admin".to_vec())
        );
        let different_order = PmOperator::new("root ADMIN").unwrap();
        assert_ne!(
            first.automaton_address(),
            different_order.automaton_address()
        );
    }

    #[test]
    fn phrase_cache_uses_file_content_instead_of_path() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first.data");
        let second_path = directory.path().join("second.data");
        std::fs::write(&first_path, "# comment\n ADMIN \nroot\n").unwrap();
        std::fs::write(&second_path, "ADMIN\nroot\n").unwrap();
        let first = PmOperator::from_file(first_path.to_str().unwrap()).unwrap();
        let second = PmOperator::from_file(second_path.to_str().unwrap()).unwrap();
        assert_eq!(first.automaton_address(), second.automaton_address());
        std::fs::write(&first_path, "changed\n").unwrap();
        let replacement = PmOperator::from_file(first_path.to_str().unwrap()).unwrap();
        assert_ne!(first.automaton_address(), replacement.automaton_address());
        assert!(!replacement.execute("ADMIN").matched);
        assert!(replacement.execute("changed").matched);
        assert!(first.execute("ADMIN").matched);
    }

    #[test]
    fn concurrent_phrase_loads_share_a_single_compiled_automaton() {
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    PmOperator::new("concurrent-phrase-cache FIRST Second").unwrap()
                })
            })
            .collect();
        let operators: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        for operator in &operators[1..] {
            assert_eq!(
                operators[0].automaton_address(),
                operator.automaton_address()
            );
        }
    }

    #[test]
    fn shared_phrase_programs_do_not_share_target_exclusions() {
        use crate::ModSecurity;
        let original = ModSecurity::from_string(
            r#"SecRule ARGS "@pm shared-phrase-rule-target" "id:1,phase:2,deny,status:403""#,
        )
        .unwrap();
        let excluded = ModSecurity::from_string(
            r#"SecRule ARGS "@pm shared-phrase-rule-target" "id:1,phase:2,deny,status:403"
SecRuleUpdateTargetById 1 "!ARGS:skip""#,
        )
        .unwrap();
        assert_eq!(
            PHRASE_CACHE.entries.lock().unwrap()[&vec!["shared-phrase-rule-target".into()]]
                .strong_count(),
            2
        );
        for (engine, should_block) in [(&original, true), (&excluded, false)] {
            let mut transaction = engine.new_transaction();
            transaction
                .process_uri("/?skip=shared-phrase-rule-target", "GET", "HTTP/1.1")
                .unwrap();
            transaction.process_request_headers().unwrap();
            transaction.process_request_body().unwrap();
            assert_eq!(transaction.has_intervention(), should_block);
        }
    }

    #[test]
    fn dropped_phrase_programs_release_automata_and_prune_stale_keys() {
        let cache = PhraseCache::default();
        let program = cache.get(vec!["retired-phrase".into()]).unwrap();
        let weak = Arc::downgrade(&program);
        drop(program);
        assert!(weak.upgrade().is_none(), "the cache must not own programs");
        let live = cache.get(vec!["live-phrase".into()]).unwrap();
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(Arc::ptr_eq(
            &live,
            &entries[&vec!["live-phrase".into()]].upgrade().unwrap()
        ));
    }

    #[test]
    fn test_pm_simple() {
        let op = PmOperator::new("admin root user").unwrap();
        assert!(op.execute("the admin user").matched);
        assert!(!op.execute("guest").matched);
    }

    #[test]
    fn test_pm_case_insensitive() {
        let op = PmOperator::new("ADMIN").unwrap();
        assert!(op.execute("admin").matched);
        assert!(op.execute("Admin").matched);
    }
}
