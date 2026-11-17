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

/// Numeric equals operator (@eq).
/// Supports both numeric literals and variable references (e.g., %{tx.var}).
pub struct EqOperator {
    /// The argument (may be a number or variable reference).
    arg: String,
}

impl EqOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(value: &str) -> Self {
        Self {
            arg: value.to_string(),
        }
    }

    fn target_value(&self) -> Option<i64> {
        // If it's a variable reference, we can't resolve it statically
        if self.arg.contains("%{") {
            return None;
        }
        Some(numeric_value(self.arg.as_bytes()))
    }
}

impl Operator for EqOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(
            if self
                .target_value()
                .is_some_and(|target| numeric_value(value) == target)
            {
                ByteOperatorResult::matched(value.to_vec())
            } else {
                ByteOperatorResult::no_match()
            },
        )
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if self
            .target_value()
            .is_some_and(|target| numeric_value(value.as_bytes()) == target)
        {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "eq"
    }
}

/// Greater than operator (@gt).
pub struct GtOperator {
    arg: String,
}

impl GtOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(value: &str) -> Self {
        Self {
            arg: value.to_string(),
        }
    }

    fn target_value(&self) -> Option<i64> {
        if self.arg.contains("%{") {
            return None;
        }
        Some(numeric_value(self.arg.as_bytes()))
    }
}

impl Operator for GtOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(
            if self
                .target_value()
                .is_some_and(|target| numeric_value(value) > target)
            {
                ByteOperatorResult::matched(value.to_vec())
            } else {
                ByteOperatorResult::no_match()
            },
        )
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if self
            .target_value()
            .is_some_and(|target| numeric_value(value.as_bytes()) > target)
        {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "gt"
    }
}

/// Less than operator (@lt).
pub struct LtOperator {
    arg: String,
}

impl LtOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(value: &str) -> Self {
        Self {
            arg: value.to_string(),
        }
    }

    fn target_value(&self) -> Option<i64> {
        if self.arg.contains("%{") {
            return None;
        }
        Some(numeric_value(self.arg.as_bytes()))
    }
}

impl Operator for LtOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(
            if self
                .target_value()
                .is_some_and(|target| numeric_value(value) < target)
            {
                ByteOperatorResult::matched(value.to_vec())
            } else {
                ByteOperatorResult::no_match()
            },
        )
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if self
            .target_value()
            .is_some_and(|target| numeric_value(value.as_bytes()) < target)
        {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "lt"
    }
}

/// Greater than or equal operator (@ge).
pub struct GeOperator {
    arg: String,
}

impl GeOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(value: &str) -> Self {
        Self {
            arg: value.to_string(),
        }
    }

    fn target_value(&self) -> Option<i64> {
        if self.arg.contains("%{") {
            return None;
        }
        Some(numeric_value(self.arg.as_bytes()))
    }
}

impl Operator for GeOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(
            if self
                .target_value()
                .is_some_and(|target| numeric_value(value) >= target)
            {
                ByteOperatorResult::matched(value.to_vec())
            } else {
                ByteOperatorResult::no_match()
            },
        )
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if self
            .target_value()
            .is_some_and(|target| numeric_value(value.as_bytes()) >= target)
        {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "ge"
    }
}

/// Less than or equal operator (@le).
pub struct LeOperator {
    arg: String,
}

impl LeOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(value: &str) -> Self {
        Self {
            arg: value.to_string(),
        }
    }

    fn target_value(&self) -> Option<i64> {
        if self.arg.contains("%{") {
            return None;
        }
        Some(numeric_value(self.arg.as_bytes()))
    }
}

impl Operator for LeOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(
            if self
                .target_value()
                .is_some_and(|target| numeric_value(value) <= target)
            {
                ByteOperatorResult::matched(value.to_vec())
            } else {
                ByteOperatorResult::no_match()
            },
        )
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if self
            .target_value()
            .is_some_and(|target| numeric_value(value.as_bytes()) <= target)
        {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "le"
    }
}

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
