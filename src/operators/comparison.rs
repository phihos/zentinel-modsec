//! Comparison operators (@contains, @eq, @gt, etc.).

use super::traits::{ByteOperatorResult, Operator, OperatorResult};

/// Contains operator (@contains).
pub struct ContainsOperator {
    needle: String,
}

impl ContainsOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(needle: &str) -> Self {
        Self {
            needle: needle.to_string(),
        }
    }
}

impl Operator for ContainsOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(
            if self.needle.is_empty()
                || value
                    .windows(self.needle.len())
                    .any(|w| w == self.needle.as_bytes())
            {
                ByteOperatorResult::matched(self.needle.as_bytes().to_vec())
            } else {
                ByteOperatorResult::no_match()
            },
        )
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if value.contains(&self.needle) {
            OperatorResult::matched(self.needle.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "contains"
    }
}

/// Case-sensitive `@containsWord` with ModSecurity v3's ASCII-letter boundaries.
pub(super) struct ContainsWordOperator {
    finder: memchr::memmem::Finder<'static>,
}

impl ContainsWordOperator {
    pub(super) fn new(needle: &[u8]) -> Self {
        Self {
            finder: memchr::memmem::Finder::new(needle).into_owned(),
        }
    }

    fn find(&self, value: &[u8]) -> ByteOperatorResult {
        let needle = self.finder.needle();
        if needle.is_empty() {
            return ByteOperatorResult::matched(Vec::new());
        }
        let mut start = 0;
        while let Some(offset) = self.finder.find(&value[start..]) {
            let pos = start + offset;
            let end = pos + needle.len();
            if (pos == 0 || !value[pos - 1].is_ascii_alphabetic())
                && (end == value.len() || !value[end].is_ascii_alphabetic())
            {
                return ByteOperatorResult::matched(needle);
            }
            // The next acceptable occurrence may overlap this rejected one.
            start = pos + 1;
        }
        ByteOperatorResult::no_match()
    }
}

impl Operator for ContainsWordOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(self.find(value))
    }

    fn execute(&self, value: &str) -> OperatorResult {
        self.find(value.as_bytes()).into_text()
    }

    fn name(&self) -> &'static str {
        "containsWord"
    }
}

/// BeginsWith operator (@beginsWith).
pub struct BeginsWithOperator {
    prefix: String,
}

impl BeginsWithOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
        }
    }
}

impl Operator for BeginsWithOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(if value.starts_with(self.prefix.as_bytes()) {
            ByteOperatorResult::matched(self.prefix.as_bytes().to_vec())
        } else {
            ByteOperatorResult::no_match()
        })
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if value.starts_with(&self.prefix) {
            OperatorResult::matched(self.prefix.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "beginsWith"
    }
}

/// EndsWith operator (@endsWith).
pub struct EndsWithOperator {
    suffix: String,
}

impl EndsWithOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(suffix: &str) -> Self {
        Self {
            suffix: suffix.to_string(),
        }
    }
}

impl Operator for EndsWithOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(if value.ends_with(self.suffix.as_bytes()) {
            ByteOperatorResult::matched(self.suffix.as_bytes().to_vec())
        } else {
            ByteOperatorResult::no_match()
        })
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if value.ends_with(&self.suffix) {
            OperatorResult::matched(self.suffix.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "endsWith"
    }
}

/// String equals operator (@streq).
pub struct StreqOperator {
    expected: String,
}

impl StreqOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(expected: &str) -> Self {
        Self {
            expected: expected.to_string(),
        }
    }
}

impl Operator for StreqOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(if value == self.expected.as_bytes() {
            ByteOperatorResult::matched(value.to_vec())
        } else {
            ByteOperatorResult::no_match()
        })
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if value == self.expected {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "streq"
    }
}

// Pinned Coraza's numeric operators use strconv.Atoi and ignore its error.
// Syntax errors become zero; signed 64-bit overflows retain the clamped value.
// Work on original bytes: invalid UTF-8 is a syntax error, not absent input.
fn numeric_value(bytes: &[u8]) -> i64 {
    let (negative, digits) = match bytes.first() {
        Some(b'-') => (true, &bytes[1..]),
        Some(b'+') => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    let saturated = if negative { i64::MIN } else { i64::MAX };
    let mut value = 0u64;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return 0;
        }
        let Some(next) = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(byte - b'0')))
        else {
            // strconv.ParseUint returns immediately on unsigned overflow,
            // even if later bytes would have been invalid syntax.
            return saturated;
        };
        value = next;
    }
    if negative {
        if value >= 1u64 << 63 {
            i64::MIN
        } else {
            -(value as i64)
        }
    } else {
        value.min(i64::MAX as u64) as i64
    }
}

// A numeric target is parsed once. Values and expanded arguments use the
// same original-byte conversion, including Go's overflow behavior.
macro_rules! numeric_operator {
    ($operator:ident, $name:literal, $comparison:tt) => {
        #[doc = concat!("Numeric comparison operator (@", $name, ").")]
        pub struct $operator {
            target: Option<i64>,
        }

        impl $operator {
            /// Compile a static argument. Runtime macros are bound by the transaction.
            pub fn new(argument: &str) -> Self {
                Self {
                    target: (!argument.contains("%{")).then(|| numeric_value(argument.as_bytes())),
                }
            }

            pub(super) fn from_expanded(argument: &[u8]) -> Self {
                Self { target: Some(numeric_value(argument)) }
            }

            fn matches(&self, value: &[u8]) -> bool {
                self.target.is_some_and(|target| numeric_value(value) $comparison target)
            }
        }

        impl Operator for $operator {
            fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
                Ok(if self.matches(value) {
                    ByteOperatorResult::matched(value.to_vec())
                } else {
                    ByteOperatorResult::no_match()
                })
            }

            fn execute(&self, value: &str) -> OperatorResult {
                if self.matches(value.as_bytes()) {
                    OperatorResult::matched(value.to_owned())
                } else {
                    OperatorResult::no_match()
                }
            }

            fn name(&self) -> &'static str {
                $name
            }
        }
    };
}

numeric_operator!(EqOperator, "eq", ==);
numeric_operator!(GtOperator, "gt", >);
numeric_operator!(GeOperator, "ge", >=);
numeric_operator!(LtOperator, "lt", <);
numeric_operator!(LeOperator, "le", <=);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains() {
        let op = ContainsOperator::new("admin");
        assert!(op.execute("/admin/users").matched);
        assert!(!op.execute("/users").matched);
    }

    #[test]
    fn test_begins_with() {
        let op = BeginsWithOperator::new("/admin");
        assert!(op.execute("/admin/users").matched);
        assert!(!op.execute("/users/admin").matched);
    }

    #[test]
    fn test_ends_with() {
        let op = EndsWithOperator::new(".php");
        assert!(op.execute("index.php").matched);
        assert!(!op.execute("index.html").matched);
    }

    #[test]
    fn test_streq() {
        let op = StreqOperator::new("admin");
        assert!(op.execute("admin").matched);
        assert!(!op.execute("Admin").matched);
    }

    #[test]
    fn test_numeric_operators() {
        let eq = EqOperator::new("10");
        assert!(eq.execute("10").matched);
        assert!(!eq.execute("11").matched);

        let gt = GtOperator::new("10");
        assert!(gt.execute("11").matched);
        assert!(!gt.execute("10").matched);

        let lt = LtOperator::new("10");
        assert!(lt.execute("9").matched);
        assert!(!lt.execute("10").matched);
    }
}
