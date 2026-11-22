//! `@rx` may rule a value out before running the regex, from what the pattern
//! says every match needs. That must never change a result: the operator has
//! to agree with the plain regex on whether a value matches, on the matched
//! text and on every capture group.

use regex::Regex;
use zentinel_modsec::operators::{Operator, RxOperator};
use zentinel_modsec::ModSecurity;

/// What the plain regex says: the matched text and the groups, a group that
/// took no part being empty.
fn plain(regex: &Regex, value: &str) -> Option<(String, Vec<String>)> {
    regex.captures(value).map(|captures| {
        let groups = captures
            .iter()
            .skip(1)
            .map(|group| group.map(|m| m.as_str().to_string()).unwrap_or_default())
            .collect();
        (captures[0].to_string(), groups)
    })
}

fn operator(rx: &RxOperator, value: &str) -> Option<(String, Vec<String>)> {
    let result = rx.execute(value);
    result.matched.then(|| {
        (
            result.matched_value.expect("a match reports its text"),
            result.captures,
        )
    })
}

fn assert_agrees(pattern: &str, rx: &RxOperator, regex: &Regex, value: &str) {
    assert_eq!(
        operator(rx, value),
        plain(regex, value),
        "pattern {pattern:?} on value {value:?}"
    );
}

/// xorshift64*: deterministic, so a failure names the same case every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

fn text(rng: &mut Rng, alphabet: &[&str], length: usize) -> String {
    (0..length).map(|_| rng.pick(alphabet)).collect()
}

/// Only letters and digits.
const ALPHANUMERIC: &[&str] = &["a", "b", "s", "e", "l", "A", "S", "E", "0", "9"];
/// Letters, digits and the punctuation of names and paths.
const TOKEN: &[&str] = &[
    "a", "b", "s", "e", "l", "A", "S", "E", "0", "9", "-", "/", ".", ":", "_",
];
/// Everything the generated patterns can ask for, and more.
const MIXED: &[&str] = &[
    "a", "b", "s", "e", "l", "A", "S", "E", "0", "9", "-", "/", ".", ":", "_", "<", ">", "=", "%",
    " ", "\\", "\n", "é", "É", "ſ", "K", "'", "(", ";",
];

/// Lengths on both sides of every bound a check could have.
const LENGTHS: &[usize] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 24, 63, 64, 65, 66, 127, 128, 129, 130,
];

fn values(rng: &mut Rng) -> Vec<String> {
    let mut values = Vec::new();
    for &length in LENGTHS {
        for alphabet in [ALPHANUMERIC, TOKEN, MIXED] {
            values.push(text(rng, alphabet, length));
        }
    }
    values
}

/// Patterns in the shapes CRS writes, each with values it matches.
const SHAPES: &[(&str, &[&str])] = &[
    (
        r"^[\w/.+*-]+(?:\s?;\s*(?:action|boundary|charset|component|start(?:-info)?|type|version)\s?=\s?['\x22\w.()+,/:=?<>@#*-]+)*$",
        &["text/html", "text/html; charset=utf-8"],
    ),
    (r"^(?:GET|HEAD)$", &["GET", "HEAD"]),
    (r"^\d+$", &["0", "1234567890"]),
    (r"^0?$", &["", "0"]),
    (
        r"^bytes=(?:(?:\d+)?-(?:\d+)?\s*,?\s*){6}",
        &["bytes=1-2,3-4,5-6,7-8,9-10,11-12"],
    ),
    (
        r"(?i)^(?:ht|f)tps?://(.*?)/",
        &["http://example.com/", "FTPS://Host/x"],
    ),
    (
        r"(?:^|[/;\x5c])\.{2,3}[/;\x5c]",
        &["../", "a/..\\b", ";.../"],
    ),
    (
        r"(?i)(?:\x5c|%(?:c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|2(?:5(?:c(?:0%25af|1%259c)|2f|5c)|%46|f)|(?:(?:f(?:8%8)?0%8|e)0%80%a|bg%q)f|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|u(?:221[56]|002f|EFC8|F025)|1u|5c)|0x(?:2f|5c)|/)(?:%(?:(?:f(?:(?:c%80|8)%8)?0%8|e)0%80%ae|2(?:(?:5(?:c0%25a|2))?e|%45)|u(?:(?:002|ff0)e|2024)|%32(?:%(?:%6|4)5|E)|c0(?:%[256aef]e|\.))|\.(?:%0[01]|\?)?|\?\.?|0x2e){2,3}(?:\x5c|%(?:c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|2(?:5(?:c(?:0%25af|1%259c)|2f|5c)|%46|f)|(?:(?:f(?:8%8)?0%8|e)0%80%a|bg%q)f|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|u(?:221[56]|002f|EFC8|F025)|1u|5c)|0x(?:2f|5c)|/)",
        &["/../", "%2f..%2f", "/%2e%2e/", "0x2f..0x5c"],
    ),
    (
        r"(?i)<script[^>]*>[\s\S]*?",
        &["<script>", "<SCRIPT src=x>alert(1)"],
    ),
    (
        r"(?i)[\s\S](?:\b(?:x(?:link:href|html|mlns)|data:text/html|formaction|pattern\b.*?=)|!ENTITY\s+(?:%\s+)?\S+\s+(?:SYSTEM|PUBLIC)|@import|;base64)\b",
        &[" xlink:href", "a;base64 ", "<!ENTITY x SYSTEM"],
    ),
    (
        r"(?i)\b(?:s(?:tyle|rc)|href)\b[\s\S]*?=",
        &["src=", "a STYLE  ="],
    ),
    (
        r"(?i:union.*?select)",
        &["union select", "UNION/**/SELECT 1"],
    ),
    (
        r"(?i)\b(?:and|or)\b\s*?['\x22\d]+\s*?=\s*?['\x22\d]+",
        &["1 or 1=1", "x' AND '1'='1"],
    ),
    (
        r"(?i)(?:sleep\(\s*?\d*?\s*?\)|benchmark\(.*?,.*?\))",
        &["sleep(5)", "BENCHMARK(1,2)"],
    ),
    (r"['\x22`;]", &["'", "a;b"]),
    (r"[\n\r]", &["a\nb", "\r"]),
    (
        r"[\n\r]+(?:\s|location|refresh|(?:set-)?cookie|(?:x-)?(?:forwarded-(?:for|host|server)|host|via|remote-ip|remote-addr|originating-IP))\s*:",
        &["\nlocation:", "\r\nset-cookie :"],
    ),
    (
        r"(?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)(?:[^}]{0,15}(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)|jndi|ctx)",
        &["${jndi", "${${", "&dollar;&lbrace;ctx"],
    ),
    (r"\.(?:bak|conf|sql|inc)$", &["x.bak", ".sql"]),
    (
        r"^(?:(?:max-age=[0-9]+|min-fresh=[0-9]+|no-cache|no-store|no-transform|only-if-cached|max-stale(?:=[0-9]+)?)(?:\s*,\s*|$)){1,7}$",
        &["no-cache", "max-age=0, no-store"],
    ),
    (r"^[^;\s]+", &["text/html", "a b"]),
    (
        r"^(?i:(?:[a-z]{3,10}\s+(?:\w{3,7}?://[\w\-\./]*(?::\d+)?)?/[^?#]*(?:\?[^#\s]*)?(?:#[\S]*)?|connect (?:(?:\d{1,3}\.){3}\d{1,3}\.?(?::\d+)?|[\w\-\./]+:\d+)|options \*)\s+[\w\./]+|get /[^?#]*(?:\?[^#\s]*)?(?:#[\S]*)?)$",
        &["GET / HTTP/1.1", "get /a?b", "OPTIONS * HTTP/1.1"],
    ),
    (
        r"(?:\b|_)(?:etc|proc)/(?:passwd|self)\b",
        &["/etc/passwd", "_proc/self"],
    ),
    (r"(\d+)-(\d+)", &["1-2", "bytes=10-200"]),
    (r"^(a)?(b)?c", &["c", "ac", "bc", "abc"]),
    (r"(?i)é+ſ?", &["é", "ÉÉſ"]),
    (r"\bk\b", &["k", "a k b"]),
    (r"(?i)k", &["k", "K", "\u{212a}"]),
    (r"(?s)a.b", &["a\nb", "a-b"]),
    (r"(?m)^end$", &["end", "a\nend\nb"]),
    (r"(?x) a b \s c", &["ab c"]),
    (r"a{3}b{0,2}", &["aaa", "aaabb"]),
    (r"(?:a|)b", &["b", "ab"]),
    (r"(?:)", &["", "anything"]),
    (r"\x00", &["\0"]),
    (r"[^a-z0-9]", &["-", "A"]),
    (r"(?-u:\w)+-(?-u:\d)", &["ab-1"]),
    (r"\p{Greek}+", &["αβγ"]),
];

#[test]
fn shapes_match_their_examples() {
    for (pattern, examples) in SHAPES {
        let rx = RxOperator::new(pattern).expect("pattern compiles");
        for example in *examples {
            assert!(
                rx.execute(example).matched,
                "pattern {pattern:?} should match {example:?}"
            );
        }
    }
}

#[test]
fn shapes_agree_with_the_plain_regex() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let random = values(&mut rng);
    for (pattern, examples) in SHAPES {
        let rx = RxOperator::new(pattern).expect("pattern compiles");
        let regex = Regex::new(pattern).expect("pattern compiles");
        for value in &random {
            assert_agrees(pattern, &rx, &regex, value);
        }
        for example in *examples {
            // Every piece of a matching value, so that values just short of a
            // match and just long enough for one are both covered.
            let cuts: Vec<usize> = example
                .char_indices()
                .map(|(at, _)| at)
                .chain([example.len()])
                .collect();
            for &start in &cuts {
                for &end in cuts.iter().filter(|&&end| end >= start) {
                    assert_agrees(pattern, &rx, &regex, &example[start..end]);
                }
            }
            // The example inside a value, and padded past the length bounds.
            for padding in [1, 7, 60, 64, 125, 128] {
                let before = text(&mut rng, ALPHANUMERIC, padding);
                let after = text(&mut rng, TOKEN, padding);
                assert_agrees(pattern, &rx, &regex, &format!("{before}{example}"));
                assert_agrees(pattern, &rx, &regex, &format!("{example}{after}"));
                assert_agrees(pattern, &rx, &regex, &format!("{before}{example}{after}"));
            }
        }
    }
}

#[test]
fn a_pattern_nested_deeper_than_the_analysis_follows_agrees() {
    let pattern = format!("{}deep<{}", "(?:".repeat(40), ")+".repeat(40));
    let rx = RxOperator::new(&pattern).expect("pattern compiles");
    let regex = Regex::new(&pattern).expect("pattern compiles");
    let mut rng = Rng(0xDEEB_DEEB_DEEB_DEEB);
    for value in ["deep<", "deep<deep<", "deep", "eep<", "<", "", "xdeep<x"] {
        assert_agrees(&pattern, &rx, &regex, value);
    }
    for value in values(&mut rng) {
        assert_agrees(&pattern, &rx, &regex, &value);
    }
    assert!(rx.execute("deep<").matched);
}

const ATOMS: &[&str] = &[
    "a", "b", "s", "e", "l", "ab", "sel", "0", "9", "A", "E", "-", "/", r"\.", ":", "_", "<", "=",
    "%", " ", "é", r"\x5c", r"\n", "[a-z]", "[0-9]", r"\d", r"\w", r"\s", r"\W", r"\S", "[^a-z]",
    "[^<]", ".", "[a-zé]", "[/.:]", "[<>=]", "[A-Z_]", "[-/]", r"\b", r"\B", "^", "$", "(?i:s)",
    "(?i:é)", "(?i:k)", "(?i:-)",
];

const QUANTIFIERS: &[&str] = &[
    "", "", "", "", "?", "*", "+", "{2}", "{2,3}", "{0,2}", "{1,}", "??", "+?",
];

fn sequence(rng: &mut Rng, depth: usize) -> String {
    (0..1 + rng.below(4))
        .map(|_| {
            let grouped = depth > 0 && rng.below(4) == 0;
            let piece = if grouped {
                let branches: Vec<String> = (0..1 + rng.below(3))
                    .map(|_| {
                        // An empty branch makes the whole group optional.
                        if rng.below(8) == 0 {
                            String::new()
                        } else {
                            sequence(rng, depth - 1)
                        }
                    })
                    .collect();
                let open = if rng.below(2) == 0 { "(" } else { "(?:" };
                format!("{open}{})", branches.join("|"))
            } else {
                rng.pick(ATOMS).to_string()
            };
            let assertion = matches!(piece.as_str(), r"\b" | r"\B" | "^" | "$");
            let quantifier = if assertion { "" } else { rng.pick(QUANTIFIERS) };
            format!("{piece}{quantifier}")
        })
        .collect()
}

#[test]
fn generated_patterns_agree_with_the_plain_regex() {
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    let mut matches = 0;
    const PATTERNS: usize = 800;
    for _ in 0..PATTERNS {
        let flags = rng.pick(&["", "", "", "(?i)", "(?s)", "(?m)", "(?i)(?s)"]);
        let pattern = format!("{flags}{}", sequence(&mut rng, 3));
        let rx = RxOperator::new(&pattern).expect("a generated pattern compiles");
        let regex = Regex::new(&pattern).expect("a generated pattern compiles");
        for value in values(&mut rng) {
            assert_agrees(&pattern, &rx, &regex, &value);
            matches += usize::from(regex.is_match(&value));
        }
    }
    // The comparison is only worth something if both outcomes occur often.
    let total = PATTERNS * LENGTHS.len() * 3;
    assert!(
        matches > total / 10 && matches < total * 9 / 10,
        "{matches} of {total} values matched"
    );
}

fn matched(rules: &str, uri: &str) -> Vec<String> {
    let modsec = ModSecurity::from_string(rules).expect("rules load");
    let mut tx = modsec.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

#[test]
fn a_negated_rule_matches_a_value_too_short_for_the_pattern() {
    let rules = r#"
SecRuleEngine On
SecRule ARGS:a "!@rx ^[a-z]{8,}$" "id:1,phase:2,pass"
SecRule ARGS:a "@rx ^[a-z]{8,}$" "id:2,phase:2,pass"
"#;
    assert_eq!(matched(rules, "/?a=abc"), ["1"]);
    assert_eq!(matched(rules, "/?a=abcdefgh"), ["2"]);
    assert_eq!(matched(rules, "/?a="), ["1"]);
}

#[test]
fn captures_reach_tx_as_before() {
    let rules = r#"
SecRuleEngine On
SecRule ARGS:range "@rx ^bytes=(\d+)-(\d+)?$" "id:1,phase:2,pass,capture,setvar:tx.first=%{tx.1},setvar:tx.last=%{tx.2}"
SecRule TX:first "@streq 10" "id:2,phase:2,pass"
SecRule TX:last "@streq 20" "id:3,phase:2,pass"
SecRule &TX:first "@eq 0" "id:4,phase:2,pass"
"#;
    assert_eq!(matched(rules, "/?range=bytes%3D10-20"), ["1", "2", "3"]);
    assert_eq!(matched(rules, "/?range=bytes%3D10-"), ["1", "2"]);
    assert_eq!(matched(rules, "/?range=bytes"), ["4"]);
}

#[test]
fn multi_match_tests_each_stage_on_its_own() {
    // The raw value has no byte the pattern needs; the decoded one does.
    let rules = r#"
SecRuleEngine On
SecRule ARGS:a "@rx <script" "id:1,phase:2,pass,t:none,t:urlDecodeUni,t:lowercase,multiMatch"
SecRule ARGS:a "@rx %3C" "id:2,phase:2,pass,t:none,t:urlDecodeUni,multiMatch"
SecRule ARGS:a "@rx %3C" "id:3,phase:2,pass,t:none,t:urlDecodeUni"
"#;
    assert_eq!(matched(rules, "/?a=%253CSCRIPT"), ["1", "2"]);
    assert!(matched(rules, "/?a=script").is_empty());
}

#[test]
fn a_pattern_expanded_at_request_time_is_held_to_the_same_result() {
    let rules = r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:tx.word=select,setvar:tx.short=x"
SecRule ARGS:a "@rx (?i)\bunion\s+%{tx.word}\b" "id:2,phase:2,pass"
SecRule ARGS:a "!@rx (?i)\bunion\s+%{tx.word}\b" "id:3,phase:2,pass"
SecRule ARGS:b "@rx ^%{tx.short}{3}$" "id:4,phase:2,pass"
"#;
    assert_eq!(
        matched(rules, "/?a=1+UNION+SELECT+2&b=xxx"),
        ["1", "2", "4"]
    );
    assert_eq!(matched(rules, "/?a=union&b=xx"), ["1", "3"]);
}
