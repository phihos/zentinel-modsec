//! Operator trait definition.

/// Result of operator execution.
#[derive(Debug, Clone, Default)]
pub struct OperatorResult {
    /// Whether the operator matched.
    pub matched: bool,
    /// Captured groups from regex.
    pub captures: Vec<String>,
    /// The matched value.
    pub matched_value: Option<String>,
}

impl OperatorResult {
    /// Create a result indicating no match.
    pub fn no_match() -> Self {
        Self {
            matched: false,
            captures: Vec::new(),
            matched_value: None,
        }
    }

    /// Create a result indicating a match.
    pub fn matched(value: String) -> Self {
        Self {
            matched: true,
            captures: Vec::new(),
            matched_value: Some(value),
        }
    }

    /// Create a result with captures.
    pub fn matched_with_captures(value: String, captures: Vec<String>) -> Self {
        Self {
            matched: true,
            captures,
            matched_value: Some(value),
        }
    }
}

/// Operator result retaining original byte captures and matched portions.
#[derive(Debug, Clone, Default)]
pub struct ByteOperatorResult {
    /// Whether the operator matched.
    pub matched: bool,
    /// Original captured bytes; never a UTF-8 replacement string.
    pub captures: Vec<Vec<u8>>,
    /// The original matched portion when supplied by the operator.
    pub matched_value: Option<Vec<u8>>,
}

impl ByteOperatorResult {
    /// A positive match with an original byte portion.
    pub fn matched(value: impl Into<Vec<u8>>) -> Self {
        Self {
            matched: true,
            captures: vec![],
            matched_value: Some(value.into()),
        }
    }
    /// A negative match.
    pub fn no_match() -> Self {
        Self::default()
    }
    /// Present a result through the legacy UTF-8 interface.
    ///
    /// Binary values are escaped for display; byte-aware evaluation never
    /// round-trips this presentation back into another operator.
    pub fn into_text(self) -> OperatorResult {
        OperatorResult {
            matched: self.matched,
            captures: self
                .captures
                .into_iter()
                .map(|v| crate::variables::ByteValue::from(v).to_string())
                .collect(),
            matched_value: self
                .matched_value
                .map(|v| crate::variables::ByteValue::from(v).to_string()),
        }
    }
}
impl From<OperatorResult> for ByteOperatorResult {
    fn from(value: OperatorResult) -> Self {
        Self {
            matched: value.matched,
            captures: value.captures.into_iter().map(String::into_bytes).collect(),
            matched_value: value.matched_value.map(String::into_bytes),
        }
    }
}

/// Trait for all operators.
pub trait Operator: Send + Sync {
    /// Execute the operator against a value.
    fn execute(&self, value: &str) -> OperatorResult;

    /// Execute against original bytes.
    ///
    /// Custom text-only operators receive an explicit error for invalid UTF-8;
    /// override this method to support binary input without changing its bytes.
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        let text =
            std::str::from_utf8(value).map_err(|_| crate::Error::UnsupportedBinaryInput {
                component: format!("@{}", self.name()),
            })?;
        Ok(self.execute(text).into())
    }

    /// Evaluate a rule that may discard subgroups. The decision and matched
    /// portion retain the semantics of `execute_bytes`. Custom operators can
    /// keep returning their full result without implementing this method.
    fn execute_rule_bytes(
        &self,
        value: &[u8],
        _capture: bool,
    ) -> crate::Result<ByteOperatorResult> {
        self.execute_bytes(value)
    }

    /// Evaluate a REST path match and publish its named arguments to the transaction.
    fn execute_with_path_arguments(
        &self,
        value: &[u8],
        _write: &mut dyn FnMut(&str, &[u8]),
    ) -> crate::Result<ByteOperatorResult> {
        self.execute_bytes(value)
    }

    /// Minimum matching byte lengths on ASCII alphanumerics and on path tokens
    /// (alphanumerics plus `_-./:`), capped at 65. Zero disables a bound.
    fn short_token_minimums(&self) -> [u8; 2] {
        self.compiled_regex()
            .map_or([0; 2], |rx| rx.token_minimums())
    }

    /// Minimum width for alphanumeric or dotted values, capped at 65.
    fn dotted_token_minimum(&self) -> u8 {
        self.compiled_regex().map_or(0, |rx| rx.dotted_minimum())
    }

    /// Expose a compiled regex when it completely describes this operator's
    /// byte matching and capture behavior, including empty and binary matches.
    fn compiled_regex(&self) -> Option<&super::RxOperator> {
        None
    }

    /// Return a static numeric predicate when a successful match always
    /// covers the entire input and has no subgroups.
    fn numeric_comparison(&self) -> Option<super::NumericComparison> {
        None
    }

    /// Get the operator name.
    fn name(&self) -> &'static str;

    /// Whether this operator supports capture groups.
    fn supports_capture(&self) -> bool {
        false
    }
}
