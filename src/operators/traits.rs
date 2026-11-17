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

    /// Get the operator name.
    fn name(&self) -> &'static str;

    /// Whether this operator supports capture groups.
    fn supports_capture(&self) -> bool {
        false
    }
}
