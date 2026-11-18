//! Operator implementations for ModSecurity.

mod byte_argument;
pub use byte_argument::compile_operator_bytes;
mod comparison;
mod detection;
mod network;
mod pattern;
pub(crate) mod schema;
mod traits;
mod validation;

pub use comparison::{BeginsWithOperator, ContainsOperator, EndsWithOperator, StreqOperator};
pub use comparison::{
    EqOperator, GeOperator, GtOperator, LeOperator, LtOperator, NumericComparison,
};
pub use detection::{DetectSqliOperator, DetectXssOperator};
pub use network::IpMatchOperator;
pub(crate) use pattern::token_byte;
pub use pattern::{PmOperator, RxOperator};
pub use traits::{ByteOperatorResult, Operator, OperatorResult};
pub use validation::{
    ValidateByteRangeOperator, ValidateUrlEncodingOperator, ValidateUtf8EncodingOperator,
};

use crate::error::Result;
use crate::parser::{OperatorName, OperatorSpec};
use std::sync::Arc;

/// Type alias for a compiled operator.
pub type CompiledOperator = dyn Operator;

/// Create an operator from a name and argument string.
/// This is a convenience function for testing and benchmarking.
pub fn create_operator(name: OperatorName, argument: &str) -> Result<Arc<dyn Operator>> {
    let spec = OperatorSpec {
        negated: false,
        name,
        argument: argument.to_string(),
    };
    compile_operator(&spec)
}

/// Create a compiled operator from a specification.
pub fn compile_operator(spec: &OperatorSpec) -> Result<Arc<dyn Operator>> {
    let name = &spec.name;
    let argument = &spec.argument;
    match name {
        OperatorName::Rx => Ok(Arc::new(RxOperator::new(argument)?)),
        OperatorName::Pm => Ok(Arc::new(PmOperator::new(argument)?)),
        OperatorName::PmFromFile | OperatorName::Pmf => {
            Ok(Arc::new(PmOperator::from_file(argument)?))
        }
        OperatorName::Contains => Ok(Arc::new(ContainsOperator::new(argument))),
        OperatorName::ContainsWord => Ok(Arc::new(comparison::ContainsWordOperator::new(
            argument.as_bytes(),
        ))),
        OperatorName::BeginsWith => Ok(Arc::new(BeginsWithOperator::new(argument))),
        OperatorName::EndsWith => Ok(Arc::new(EndsWithOperator::new(argument))),
        OperatorName::StreQ => Ok(Arc::new(StreqOperator::new(argument))),
        OperatorName::Eq => Ok(Arc::new(EqOperator::new(argument))),
        OperatorName::Gt => Ok(Arc::new(GtOperator::new(argument))),
        OperatorName::Lt => Ok(Arc::new(LtOperator::new(argument))),
        OperatorName::Ge => Ok(Arc::new(GeOperator::new(argument))),
        OperatorName::Le => Ok(Arc::new(LeOperator::new(argument))),
        OperatorName::DetectSqli => Ok(Arc::new(DetectSqliOperator)),
        OperatorName::DetectXss => Ok(Arc::new(DetectXssOperator)),
        OperatorName::ValidateUrlEncoding => Ok(Arc::new(ValidateUrlEncodingOperator)),
        OperatorName::ValidateUtf8Encoding => Ok(Arc::new(ValidateUtf8EncodingOperator)),
        OperatorName::IpMatch => Ok(Arc::new(IpMatchOperator::new(argument)?)),
        OperatorName::IpMatchFromFile | OperatorName::IpMatchF => {
            Ok(Arc::new(IpMatchOperator::from_file(argument)?))
        }
        OperatorName::NoMatch => Ok(Arc::new(NoMatchOperator)),
        OperatorName::UnconditionalMatch => Ok(Arc::new(UnconditionalMatchOperator)),
        OperatorName::ValidateByteRange => {
            Ok(Arc::new(ValidateByteRangeOperator::try_new(argument)?))
        }
        // Placeholder operators - acknowledge but don't match
        OperatorName::VerifyCc | OperatorName::VerifySsn | OperatorName::VerifyCpf => {
            Ok(Arc::new(NoMatchOperator))
        }
        OperatorName::ValidateSchema => Ok(Arc::new(schema::SchemaOperator::load(
            argument,
            std::path::Path::new("."),
        )?)),
        OperatorName::ValidateHash | OperatorName::ValidateDtd => Ok(Arc::new(NoMatchOperator)),
        OperatorName::Rbl | OperatorName::GeoLookup | OperatorName::GsbLookup => {
            Ok(Arc::new(NoMatchOperator))
        }
        OperatorName::InspectFile | OperatorName::FuzzyHash | OperatorName::Rsub => {
            Ok(Arc::new(NoMatchOperator))
        }
        OperatorName::Within => Ok(Arc::new(WithinOperator::new(argument))),
        OperatorName::StrMatch => Ok(Arc::new(ContainsOperator::new(argument))),
        OperatorName::Ne => Ok(Arc::new(NeOperator::new(argument))),
    }
}

/// Operator that never matches.
pub struct NoMatchOperator;

impl Operator for NoMatchOperator {
    fn execute_bytes(&self, _value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(ByteOperatorResult::no_match())
    }

    fn execute(&self, _value: &str) -> OperatorResult {
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "noMatch"
    }
}

/// Operator that always matches.
pub struct UnconditionalMatchOperator;

impl Operator for UnconditionalMatchOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(ByteOperatorResult::matched(value.to_vec()))
    }

    fn execute(&self, value: &str) -> OperatorResult {
        OperatorResult::matched(value.to_string())
    }

    fn name(&self) -> &'static str {
        "unconditionalMatch"
    }
}

/// Tests whether the argument contains the input as a byte substring.
pub struct WithinOperator {
    haystack: Vec<u8>,
}

impl WithinOperator {
    /// Create a new within operator.
    pub fn new(values: &str) -> Self {
        Self {
            haystack: values.as_bytes().to_vec(),
        }
    }

    pub(crate) fn matches(haystack: &[u8], needle: &[u8]) -> bool {
        memchr::memmem::find(haystack, needle).is_some()
    }
}

impl Operator for WithinOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(if Self::matches(&self.haystack, value) {
            ByteOperatorResult::matched(value.to_vec())
        } else {
            ByteOperatorResult::no_match()
        })
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if Self::matches(&self.haystack, value.as_bytes()) {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "within"
    }
}

/// Not equal operator.
pub struct NeOperator {
    expected: String,
}

impl NeOperator {
    /// Create a new not-equal operator.
    pub fn new(expected: &str) -> Self {
        Self {
            expected: expected.to_string(),
        }
    }
}

impl Operator for NeOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(match std::str::from_utf8(value) {
            Ok(text) => self.execute(text).into(),
            Err(_) => ByteOperatorResult::matched(value.to_vec()),
        })
    }

    fn execute(&self, value: &str) -> OperatorResult {
        // Try numeric comparison first
        if let (Ok(a), Ok(b)) = (value.parse::<i64>(), self.expected.parse::<i64>()) {
            if a != b {
                return OperatorResult::matched(value.to_string());
            }
        } else if value != self.expected {
            // String comparison
            return OperatorResult::matched(value.to_string());
        }
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "ne"
    }
}
