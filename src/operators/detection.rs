//! Detection operators (@detectSQLi, @detectXSS).
//!
//! These use the selected backend in `crate::libinjection`.

use super::traits::{ByteOperatorResult, Operator, OperatorResult};
use crate::libinjection::{self, DetectionResult};

fn operator_result(result: DetectionResult) -> OperatorResult {
    if result.is_injection {
        OperatorResult::matched(result.fingerprint.unwrap_or_default())
    } else {
        OperatorResult::no_match()
    }
}

/// SQL injection detection operator (@detectSQLi).
pub struct DetectSqliOperator;

impl Operator for DetectSqliOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(operator_result(libinjection::detect_sqli_bytes(value)?).into())
    }

    fn execute(&self, value: &str) -> OperatorResult {
        operator_result(libinjection::detect_sqli(value))
    }

    fn name(&self) -> &'static str {
        "detectSQLi"
    }
}

/// XSS detection operator (@detectXSS).
pub struct DetectXssOperator;

impl Operator for DetectXssOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(operator_result(libinjection::detect_xss_bytes(value)?).into())
    }

    fn execute(&self, value: &str) -> OperatorResult {
        operator_result(libinjection::detect_xss(value))
    }

    fn name(&self) -> &'static str {
        "detectXSS"
    }
}
