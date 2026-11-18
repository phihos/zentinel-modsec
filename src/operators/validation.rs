//! SecLang byte-range, URL-encoding and UTF-8 validation operators.

use super::traits::{ByteOperatorResult, Operator, OperatorResult};
use crate::error::{Error, Result};

/// Validates each input byte against a compiled allowlist.
pub struct ValidateByteRangeOperator {
    allowed: [bool; 256],
    empty_operand: bool,
}

impl ValidateByteRangeOperator {
    /// Construct a validator, ignoring unparseable entries for compatibility.
    /// Rule loading uses [`Self::try_new`] to report malformed configuration.
    pub fn new(spec: &str) -> Self {
        Self::parse(spec, false).expect("permissive range parsing skips invalid entries")
    }

    /// Construct a validator, rejecting malformed or out-of-bounds byte values.
    pub fn try_new(spec: &str) -> Result<Self> {
        Self::parse(spec, true)
    }

    fn parse(spec: &str, strict: bool) -> Result<Self> {
        let mut allowed = [false; 256];
        if !spec.is_empty() {
            for part in spec.split(',').map(str::trim) {
                let (lo, hi) = part.split_once('-').unwrap_or((part, part));
                match (lo.parse::<u8>(), hi.parse::<u8>()) {
                    (Ok(lo), Ok(hi)) => {
                        // As in Coraza, a descending range contributes no bytes.
                        if lo <= hi {
                            allowed[usize::from(lo)..=usize::from(hi)].fill(true);
                        }
                    }
                    _ if strict => return Err(Error::Config {
                        message: format!("invalid @validateByteRange entry '{part}' in '{spec}': expected a decimal byte or two bytes separated by '-'"),
                    }),
                    _ => {}
                }
            }
        }
        Ok(Self {
            allowed,
            empty_operand: spec.is_empty(),
        })
    }

    fn first_invalid(&self, input: &[u8]) -> Option<u8> {
        input
            .iter()
            .copied()
            .find(|&byte| !self.allowed[usize::from(byte)])
    }
}

impl Operator for ValidateByteRangeOperator {
    fn short_token_minimums(&self) -> [u8; 2] {
        if self.empty_operand {
            return [0; 2];
        }
        let allows = |is_member: fn(u8) -> bool| {
            (0..=u8::MAX).all(|byte| !is_member(byte) || self.allowed[usize::from(byte)])
        };
        [
            u8::from(allows(|b| b.is_ascii_alphanumeric())) * 65,
            u8::from(allows(super::token_byte)) * 65,
        ]
    }

    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        Ok(
            if self.empty_operand || self.first_invalid(value).is_some() {
                ByteOperatorResult::matched(value)
            } else {
                ByteOperatorResult::no_match()
            },
        )
    }
    fn execute(&self, value: &str) -> OperatorResult {
        if let Some(byte) = self.first_invalid(value.as_bytes()) {
            OperatorResult::matched(format!("invalid byte: {byte}"))
        } else if self.empty_operand {
            OperatorResult::matched(String::new())
        } else {
            OperatorResult::no_match()
        }
    }
    fn name(&self) -> &'static str {
        "validateByteRange"
    }
}

/// URL encoding validation operator (@validateUrlEncoding).
pub struct ValidateUrlEncodingOperator;

impl Operator for ValidateUrlEncodingOperator {
    fn short_token_minimums(&self) -> [u8; 2] {
        [65; 2]
    }

    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        Ok(if is_valid_url_encoding(value) {
            ByteOperatorResult::no_match()
        } else {
            ByteOperatorResult::matched(b"invalid URL encoding".as_slice())
        })
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if is_valid_url_encoding(value.as_bytes()) {
            OperatorResult::no_match()
        } else {
            OperatorResult::matched("invalid URL encoding".to_owned())
        }
    }

    fn name(&self) -> &'static str {
        "validateUrlEncoding"
    }
}

fn is_valid_url_encoding(input: &[u8]) -> bool {
    let mut pos = 0;
    while let Some(offset) = memchr::memchr(b'%', &input[pos..]) {
        pos += offset;
        // Validate a whole run before searching the literal bytes again.
        while pos < input.len() && input[pos] == b'%' {
            if pos + 2 >= input.len()
                || !input[pos + 1].is_ascii_hexdigit()
                || !input[pos + 2].is_ascii_hexdigit()
            {
                return false;
            }
            pos += 3;
        }
    }
    true
}

/// UTF-8 encoding validation operator (@validateUtf8Encoding).
pub struct ValidateUtf8EncodingOperator;

impl Operator for ValidateUtf8EncodingOperator {
    fn short_token_minimums(&self) -> [u8; 2] {
        [65; 2]
    }

    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        Ok(if std::str::from_utf8(value).is_err() {
            ByteOperatorResult::matched(b"invalid UTF-8 encoding".as_slice())
        } else {
            ByteOperatorResult::no_match()
        })
    }

    fn execute(&self, _: &str) -> OperatorResult {
        // Rust's str invariant includes embedded NUL and all Unicode scalars.
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "validateUtf8Encoding"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_url_encoding() {
        assert!(is_valid_url_encoding(b"hello%20world"));
        assert!(is_valid_url_encoding(b"test%2Fpath"));
        assert!(!is_valid_url_encoding(b"hello%2"));
        assert!(!is_valid_url_encoding(b"hello%GG"));
        assert!(is_valid_url_encoding(b"ab%00%20cd%0F%FF"));
        assert!(!is_valid_url_encoding(b"ab%00%20cd%0F%F"));
    }

    #[test]
    fn test_validate_url_encoding_operator() {
        let op = ValidateUrlEncodingOperator;
        assert!(!op.execute("hello%20world").matched); // Valid = no match
        assert!(op.execute("hello%2").matched); // Invalid = match
    }
}
