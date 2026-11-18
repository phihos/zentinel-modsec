//! SQL injection detection using fingerprint analysis.
//!
//! This is a pure Rust implementation inspired by libinjection's SQLi detector.
//! It uses pattern matching and heuristics to detect SQL injection attempts
//! in user input that may be injected into SQL queries.

use super::DetectionResult;
use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;
use regex::bytes::Regex;
use std::collections::HashSet;

/// SQL token types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenType {
    /// String literal ('foo', "bar")
    String,
    /// Numeric literal (123, 0x1f)
    Number,
    /// Operator (+, -, =, <>, etc.)
    Operator,
    /// SQL keyword (SELECT, UNION, etc.)
    Keyword,
    /// Function name (CONCAT, SUBSTR, etc.)
    Function,
    /// Variable (@var, @@global)
    Variable,
    /// Comment (-- or /* */)
    Comment,
    /// Logical operator (AND, OR, NOT)
    Logic,
    /// Comparison operator (=, <>, !=, LIKE)
    ///
    /// Part of libinjection's token taxonomy. This port folds comparisons into
    /// the operator token while tokenizing, so nothing constructs it yet; it is
    /// kept so the enum still mirrors upstream.
    #[allow(dead_code)]
    Comparison,
    /// Expression grouping (parentheses content)
    Expression,
    /// Unknown/other
    Unknown,
    /// End of input
    ///
    /// Kept to mirror libinjection's taxonomy; this port signals end of input by
    /// exhausting the iterator rather than emitting a token.
    #[allow(dead_code)]
    End,
}

impl TokenType {
    /// Get the fingerprint character for this token type.
    fn fingerprint_char(&self) -> char {
        match self {
            TokenType::String => 's',
            TokenType::Number => '1',
            TokenType::Operator => 'o',
            TokenType::Keyword => 'k',
            TokenType::Function => 'f',
            TokenType::Variable => 'v',
            TokenType::Comment => 'c',
            TokenType::Logic => '&',
            TokenType::Comparison => 'o',
            TokenType::Expression => 'E',
            TokenType::Unknown => 'U',
            TokenType::End => 'E',
        }
    }
}

/// A token from the SQL tokenizer.
#[derive(Debug, Clone)]
struct Token {
    token_type: TokenType,
    value: Vec<u8>,
}

/// SQL keywords that indicate potential injection.
static SQL_KEYWORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "TRUNCATE",
        "ALTER",
        "CREATE",
        "UNION",
        "FROM",
        "WHERE",
        "INTO",
        "VALUES",
        "SET",
        "TABLE",
        "DATABASE",
        "INDEX",
        "EXEC",
        "EXECUTE",
        "HAVING",
        "GROUP",
        "ORDER",
        "BY",
        "LIMIT",
        "OFFSET",
        "JOIN",
        "LEFT",
        "RIGHT",
        "INNER",
        "OUTER",
        "CROSS",
        "NATURAL",
        "AS",
        "ON",
        "USING",
        "CASE",
        "WHEN",
        "THEN",
        "ELSE",
        "END",
        "IF",
        "WHILE",
        "DECLARE",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "GRANT",
        "REVOKE",
        "NULL",
        "ALL",
        "DISTINCT",
        "EXISTS",
        "BETWEEN",
        "IN",
        "IS",
        "LIKE",
        "ESCAPE",
        "WAITFOR",
        "DELAY",
        "SHUTDOWN",
        "BENCHMARK",
        "SLEEP",
        "LOAD_FILE",
        "OUTFILE",
        "DUMPFILE",
        "INFORMATION_SCHEMA",
        "EXTRACTVALUE",
        "UPDATEXML",
        "FLOOR",
        "RAND",
        "COUNT",
        "CONCAT",
        "CHAR",
        "ASCII",
        "SUBSTRING",
        "SUBSTR",
        "MID",
        "VERSION",
        "USER",
        "DATABASE",
        "SCHEMA",
        "PASSWORD",
        "MD5",
        "SHA1",
        "SHA2",
        "ENCODE",
        "DECODE",
        "HEX",
        "UNHEX",
        "CONV",
        "CONVERT",
        "CAST",
    ]
    .iter()
    .cloned()
    .collect()
});

/// SQL functions.
static SQL_FUNCTIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "CONCAT",
        "SUBSTR",
        "SUBSTRING",
        "MID",
        "LENGTH",
        "LEN",
        "CHAR",
        "ASCII",
        "ORD",
        "CONV",
        "HEX",
        "UNHEX",
        "BIN",
        "OCT",
        "MD5",
        "SHA1",
        "SHA2",
        "ENCODE",
        "DECODE",
        "COMPRESS",
        "UNCOMPRESS",
        "AES_ENCRYPT",
        "AES_DECRYPT",
        "PASSWORD",
        "ENCRYPT",
        "VERSION",
        "USER",
        "DATABASE",
        "SCHEMA",
        "CURRENT_USER",
        "SESSION_USER",
        "SYSTEM_USER",
        "NOW",
        "CURDATE",
        "CURTIME",
        "UTC_DATE",
        "UTC_TIME",
        "SLEEP",
        "BENCHMARK",
        "LOAD_FILE",
        "EXTRACTVALUE",
        "UPDATEXML",
        "FLOOR",
        "RAND",
        "CEIL",
        "ROUND",
        "COUNT",
        "SUM",
        "AVG",
        "MIN",
        "MAX",
        "GROUP_CONCAT",
        "COALESCE",
        "NULLIF",
        "IFNULL",
        "NVL",
        "DECODE",
        "CASE",
        "IF",
        "IIF",
        "CONVERT",
        "CAST",
        "TRIM",
        "LTRIM",
        "RTRIM",
        "UPPER",
        "LOWER",
        "UCASE",
        "LCASE",
        "REPLACE",
        "REVERSE",
        "INSERT",
        "INSTR",
        "LOCATE",
        "POSITION",
        "FIND_IN_SET",
        "FIELD",
        "ELT",
        "MAKE_SET",
        "EXPORT_SET",
        "REPEAT",
        "SPACE",
        "LPAD",
        "RPAD",
        "LEFT",
        "RIGHT",
        "QUOTE",
        "SOUNDEX",
        "FORMAT",
    ]
    .iter()
    .cloned()
    .collect()
});

/// Known SQLi fingerprints (simplified set).
/// These are patterns that indicate SQL injection attempts.
static SQLI_FINGERPRINTS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Classic injection patterns
        "1&1", // 1 OR 1
        "s&s", // 'x' OR 'x'
        "1&s", // 1 OR 'x'
        "s&1", // 'x' OR 1
        "sok", // ' OR keyword
        "1ok", // 1 OR keyword
        "so1", // ' OR 1
        "1o1", // 1 OR 1
        "sos", // ' OR '
        "sks", // ' keyword '
        "1k1", // 1 keyword 1
        "sk1", // ' keyword 1
        "1ks", // 1 keyword '
        // Union-based injection
        "1kk", // 1 UNION SELECT
        "skk", // ' UNION SELECT
        "Ek",  // ) UNION
        "kk",  // SELECT FROM / UNION SELECT
        "kkk", // UNION SELECT FROM
        "kks", // SELECT 'x'
        "kk1", // SELECT 1
        "kkf", // SELECT function
        "kfk", // keyword function keyword
        // Comment-based
        "scs", // '/* */'
        "1c1", // 1/* */1
        "sc",  // ' --
        "1c",  // 1 --
        "ck",  // -- SELECT
        "cs",  // -- 'x'
        "c1",  // -- 1
        // Function-based
        "f",   // function()
        "fk",  // function() keyword
        "kf",  // keyword function()
        "fs",  // function('x')
        "f1",  // function(1)
        "fEk", // function() ) keyword
        // Expression-based
        "Ek",  // ) keyword
        "E&E", // ) OR (
        "Eo",  // ) operator
        "oE",  // operator (
        "EoE", // ) = (
        // Stacked queries
        "1ok", // 1; DROP
        "sok", // '; DROP
        "okk", // ; SELECT
        "ok",  // ; keyword
        // Error-based
        "kfE", // EXTRACTVALUE()
        "fkf", // function keyword function
        // Boolean-based
        "1&1o1", // 1 AND 1=1
        "s&so1", // ' AND '='
        "1&sos", // 1 AND ''='
        "so1o1", // ' OR 1=1
        // Time-based
        "kfE",  // SLEEP(5)
        "kf1E", // BENCHMARK(1000000,MD5('x'))
    ]
    .iter()
    .cloned()
    .collect()
});

/// Compiled regex patterns for SQLi detection.
static SQLI_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Classic OR/AND injection with quotes
        Regex::new(r"(?i)'\s*(or|and)\s*'").unwrap(),
        Regex::new(r"(?i)'\s*(or|and)\s+\d").unwrap(),
        Regex::new(r"(?i)'\s*(or|and)\s+\w+\s*=").unwrap(),
        Regex::new(r"(?i)\d\s*(or|and)\s+\d\s*=\s*\d").unwrap(),
        Regex::new(r"(?i)'\s*=\s*'").unwrap(),
        // Tautologies (without backreferences)
        Regex::new(r"(?i)\b1\s*=\s*1\b").unwrap(),
        Regex::new(r"(?i)\b2\s*=\s*2\b").unwrap(),
        Regex::new(r"(?i)\bor\s+1\s*=\s*1").unwrap(),
        Regex::new(r"(?i)\bor\s+'[^']*'\s*=\s*'[^']*'").unwrap(),
        Regex::new(r"(?i)\bor\s+true\b").unwrap(),
        Regex::new(r"(?i)\band\s+1\s*=\s*1").unwrap(),
        // UNION-based injection
        Regex::new(r"(?i)\bunion\s+(all\s+)?select\b").unwrap(),
        Regex::new(r"(?i)'\s*union\s+(all\s+)?select\b").unwrap(),
        Regex::new(r"(?i)\d\s+union\s+(all\s+)?select\b").unwrap(),
        // Comment injection
        Regex::new(r"(?i)'[^']*--").unwrap(),
        Regex::new(r"(?i)'[^']*/\*").unwrap(),
        Regex::new(r"(?i)\d\s*--").unwrap(),
        Regex::new(r"(?i)--\s*(select|drop|delete|update|insert|union)\b").unwrap(),
        Regex::new(r"/\*.*\*/").unwrap(),
        // Stacked queries
        Regex::new(r"(?i)';\s*(drop|delete|update|insert|select|exec|execute)\b").unwrap(),
        Regex::new(r"(?i)\d;\s*(drop|delete|update|insert|select|exec|execute)\b").unwrap(),
        Regex::new(r"(?i);\s*(drop|delete|truncate)\s+").unwrap(),
        // Time-based injection
        Regex::new(r"(?i)\b(sleep|benchmark|waitfor|delay|pg_sleep)\s*\(").unwrap(),
        // Error-based injection
        Regex::new(r"(?i)\b(extractvalue|updatexml|xmltype)\s*\(").unwrap(),
        // Dangerous keywords after quote
        Regex::new(
            r"(?i)'\s*(select|insert|update|delete|drop|truncate|exec|execute|create|alter)\b",
        )
        .unwrap(),
        // Information gathering
        Regex::new(r"(?i)\b(information_schema|sys\.tables|sysobjects)\b").unwrap(),
        // Typical SQLi endings
        Regex::new(r"(?i)'\s*or\s*'").unwrap(),
        Regex::new(r"(?i)'\s*;\s*--").unwrap(),
        // Quote followed by logical operator
        Regex::new(r"(?i)'\s*(and|or|xor)\s").unwrap(),
        // Number followed by OR/AND
        Regex::new(r"(?i)\d\s+(or|and)\s+").unwrap(),
    ]
});

/// Check if the input contains SQL injection.
pub fn is_sqli(input: &str) -> bool {
    let result = detect_sqli(input);
    result.is_injection
}

/// Get the SQLi fingerprint for input.
pub fn sqli_fingerprint(input: &str) -> Option<String> {
    let result = detect_sqli(input);
    result.fingerprint
}

/// Detect SQL injection in input.
pub fn detect_sqli(input: &str) -> DetectionResult {
    detect_sqli_bytes(input.as_bytes())
}

/// Inspect original bytes. SQL syntax is ASCII, and quoted token values keep
/// their exact spelling, even when the surrounding text is not UTF-8.
pub fn detect_sqli_bytes(input: &[u8]) -> DetectionResult {
    use std::borrow::Cow;
    let lower = if input.is_ascii() {
        if input.iter().any(u8::is_ascii_uppercase) {
            Cow::Owned(input.to_ascii_lowercase())
        } else {
            Cow::Borrowed(input)
        }
    } else {
        let mut folded = Vec::with_capacity(input.len());
        for chunk in input.utf8_chunks() {
            folded.extend_from_slice(chunk.valid().to_lowercase().as_bytes());
            folded.extend_from_slice(chunk.invalid());
        }
        Cow::Owned(folded)
    };
    // Quick check for common SQLi indicators
    if !has_sqli_indicators(&lower) {
        return DetectionResult::safe();
    }

    // Check against regex patterns
    for pattern in SQLI_PATTERNS.iter() {
        if pattern.is_match(input) {
            // Generate a simple fingerprint based on what we found
            let fingerprint = generate_simple_fingerprint(&lower);
            return DetectionResult::detected(fingerprint);
        }
    }

    // Tokenize the input for additional analysis
    let tokens = tokenize(input);

    if tokens.is_empty() {
        return DetectionResult::safe();
    }

    // Generate fingerprint
    let fingerprint = generate_fingerprint(&tokens);

    // Check against known fingerprints
    for len in [2, 3, 4, 5].iter() {
        if fingerprint.len() >= *len {
            for i in 0..=fingerprint.len() - len {
                let substr: String = fingerprint.chars().skip(i).take(*len).collect();
                if SQLI_FINGERPRINTS.contains(substr.as_str()) {
                    return DetectionResult::detected(substr);
                }
            }
        }
    }

    // Check for direct fingerprint match
    if SQLI_FINGERPRINTS.contains(fingerprint.as_str()) {
        return DetectionResult::detected(fingerprint);
    }

    // Additional heuristic checks
    if has_dangerous_patterns(&tokens) {
        return DetectionResult::detected(fingerprint);
    }

    DetectionResult::safe()
}

/// Generate a simple fingerprint based on input characteristics.
fn generate_simple_fingerprint(lower: &[u8]) -> String {
    let mut fp = String::new();

    if lower.contains(&b'\'') || lower.contains(&b'"') {
        fp.push('s');
    }
    if memchr::memmem::find(lower, b"or").is_some() || memchr::memmem::find(lower, b"and").is_some()
    {
        fp.push('&');
    }
    if memchr::memmem::find(lower, b"union").is_some()
        || memchr::memmem::find(lower, b"select").is_some()
    {
        fp.push('k');
    }
    if memchr::memmem::find(lower, b"--").is_some() || memchr::memmem::find(lower, b"/*").is_some()
    {
        fp.push('c');
    }
    if lower.iter().any(u8::is_ascii_digit) {
        fp.push('1');
    }

    if fp.is_empty() {
        fp.push_str("sqli");
    }

    fp
}

/// Quick check for SQLi indicators.
fn has_sqli_indicators(lower: &[u8]) -> bool {
    static INDICATORS: Lazy<AhoCorasick> = Lazy::new(|| {
        AhoCorasick::new([
            "'",
            "\"",
            "--",
            "/*",
            "union",
            "select",
            " or ",
            " and ",
            "1=1",
            "'='",
            ";",
            "exec",
            "drop",
            "insert",
            "update",
            "delete",
            "benchmark",
            "sleep",
            "waitfor",
        ])
        .expect("literal SQL indicator patterns")
    });
    INDICATORS.is_match(lower)
}

/// Tokenize SQL-like input.
fn tokenize(input: &[u8]) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < input.len() {
        let c = input[i];

        // Skip whitespace
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // String literal
        if c == b'\'' || c == b'"' {
            let quote = c;
            let mut value = Vec::new();
            i += 1;
            while i < input.len() && input[i] != quote {
                if input[i] == b'\\' && i + 1 < input.len() {
                    value.push(input[i + 1]);
                    i += 2;
                } else {
                    value.push(input[i]);
                    i += 1;
                }
            }
            i += 1; // Skip closing quote
            tokens.push(Token {
                token_type: TokenType::String,
                value,
            });
            continue;
        }

        // Comment
        if c == b'-' && i + 1 < input.len() && input[i + 1] == b'-' {
            let mut value = b"--".to_vec();
            i += 2;
            while i < input.len() && input[i] != b'\n' {
                value.push(input[i]);
                i += 1;
            }
            tokens.push(Token {
                token_type: TokenType::Comment,
                value,
            });
            continue;
        }

        if c == b'/' && i + 1 < input.len() && input[i + 1] == b'*' {
            let mut value = b"/*".to_vec();
            i += 2;
            while i + 1 < input.len() && !(input[i] == b'*' && input[i + 1] == b'/') {
                value.push(input[i]);
                i += 1;
            }
            if i + 1 < input.len() {
                value.extend_from_slice(b"*/");
                i += 2;
            }
            tokens.push(Token {
                token_type: TokenType::Comment,
                value,
            });
            continue;
        }

        // Number
        if c.is_ascii_digit() || (c == b'0' && i + 1 < input.len() && input[i + 1] == b'x') {
            let mut value = Vec::new();
            // Handle hex
            if c == b'0' && i + 1 < input.len() && input[i + 1] == b'x' {
                value.extend_from_slice(b"0x");
                i += 2;
                while i < input.len() && input[i].is_ascii_hexdigit() {
                    value.push(input[i]);
                    i += 1;
                }
            } else {
                while i < input.len() && (input[i].is_ascii_digit() || input[i] == b'.') {
                    value.push(input[i]);
                    i += 1;
                }
            }
            tokens.push(Token {
                token_type: TokenType::Number,
                value,
            });
            continue;
        }

        // Word (keyword, function, identifier)
        if c.is_ascii_alphabetic() || c == b'_' || c == b'@' {
            let mut value = Vec::new();
            while i < input.len()
                && (input[i].is_ascii_alphanumeric() || input[i] == b'_' || input[i] == b'@')
            {
                value.push(input[i]);
                i += 1;
            }

            // Only ASCII bytes can enter a word token.
            let upper = std::str::from_utf8(&value)
                .expect("ASCII word")
                .to_ascii_uppercase();
            let token_type = if value.starts_with(b"@") {
                TokenType::Variable
            } else if upper == "AND" || upper == "OR" || upper == "NOT" || upper == "XOR" {
                TokenType::Logic
            } else if SQL_FUNCTIONS.contains(upper.as_str()) {
                TokenType::Function
            } else if SQL_KEYWORDS.contains(upper.as_str()) {
                TokenType::Keyword
            } else {
                TokenType::Unknown
            };

            tokens.push(Token { token_type, value });
            continue;
        }

        // Operators
        if b"=<>!+-*/%&|^~".contains(&c) {
            let mut value = Vec::new();
            value.push(c);
            i += 1;
            // Check for multi-char operators
            if i < input.len() {
                let next = input[i];
                if (c == b'<' && (next == b'=' || next == b'>'))
                    || (c == b'>' && next == b'=')
                    || (c == b'!' && next == b'=')
                    || (c == b'|' && next == b'|')
                    || (c == b'&' && next == b'&')
                {
                    value.push(next);
                    i += 1;
                }
            }
            tokens.push(Token {
                token_type: TokenType::Operator,
                value,
            });
            continue;
        }

        // Parentheses
        if c == b'(' || c == b')' {
            tokens.push(Token {
                token_type: TokenType::Expression,
                value: vec![c],
            });
            i += 1;
            continue;
        }

        // Semicolon (statement separator)
        if c == b';' {
            tokens.push(Token {
                token_type: TokenType::Operator,
                value: vec![b';'],
            });
            i += 1;
            continue;
        }

        // Skip unknown character
        i += 1;
    }

    tokens
}

/// Generate a fingerprint from tokens.
fn generate_fingerprint(tokens: &[Token]) -> String {
    tokens
        .iter()
        .map(|t| t.token_type.fingerprint_char())
        .collect()
}

/// Check for dangerous patterns in tokens.
fn has_dangerous_patterns(tokens: &[Token]) -> bool {
    if tokens.windows(2).any(|pair| {
        pair[0].value.eq_ignore_ascii_case(b"UNION")
            && pair[1].value.eq_ignore_ascii_case(b"SELECT")
    }) {
        return true;
    }

    // Check for comment followed by keyword
    for i in 0..tokens.len().saturating_sub(1) {
        if tokens[i].token_type == TokenType::Comment
            && tokens[i + 1].token_type == TokenType::Keyword
        {
            return true;
        }
    }

    // Check for multiple SQL keywords in sequence
    let keyword_count = tokens
        .iter()
        .filter(|t| t.token_type == TokenType::Keyword)
        .count();
    if keyword_count >= 3 {
        return true;
    }

    // Check for tautology (1=1, 'a'='a')
    for window in tokens.windows(3) {
        let (left, op, right) = (&window[0], &window[1], &window[2]);
        if op.token_type == TokenType::Operator
            && op.value == b"="
            && ((left.token_type == TokenType::Number
                && right.token_type == TokenType::Number
                && left.value == right.value)
                || (left.token_type == TokenType::String
                    && right.token_type == TokenType::String
                    && left.value == right.value))
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classic_injection() {
        assert!(is_sqli("1' OR '1'='1"));
        assert!(is_sqli("' OR 1=1--"));
        assert!(is_sqli("admin'--"));
        assert!(is_sqli("1 OR 1=1"));
    }

    #[test]
    fn test_union_injection() {
        assert!(is_sqli("1 UNION SELECT * FROM users"));
        assert!(is_sqli("' UNION SELECT username, password FROM users--"));
        assert!(is_sqli("1' UNION SELECT NULL,NULL,NULL--"));
    }

    #[test]
    fn test_comment_injection() {
        assert!(is_sqli("admin'/*"));
        assert!(is_sqli("1--"));
        assert!(is_sqli("'/* comment */"));
    }

    #[test]
    fn test_stacked_queries() {
        assert!(is_sqli("1; DROP TABLE users"));
        assert!(is_sqli("'; DELETE FROM users--"));
    }

    #[test]
    fn test_safe_input() {
        assert!(!is_sqli("hello world"));
        assert!(!is_sqli("normal search query"));
        assert!(!is_sqli("user@example.com"));
        assert!(!is_sqli("John O'Brien")); // Might have false positive, but it's a name
    }

    #[test]
    fn test_fingerprint() {
        let fp = sqli_fingerprint("1' OR '1'='1");
        assert!(fp.is_some());
    }
}
