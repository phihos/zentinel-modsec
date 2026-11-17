//! Detection operators (@detectSQLi, @detectXSS).
//!
//! These use the selected backend in `crate::libinjection`.

use super::traits::{ByteOperatorResult, Operator, OperatorResult};
use crate::libinjection;

/// SQL injection detection operator (@detectSQLi).
pub struct DetectSqliOperator;

impl Operator for DetectSqliOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        let result = libinjection::detect_sqli_bytes(value)?;
        Ok(if result.is_injection {
            ByteOperatorResult::matched(result.fingerprint.unwrap_or_default().into_bytes())
        } else {
            ByteOperatorResult::no_match()
        })
    }

    fn execute(&self, value: &str) -> OperatorResult {
        let result = libinjection::detect_sqli(value);
        if result.is_injection {
            OperatorResult::matched(result.fingerprint.unwrap_or_default())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "detectSQLi"
    }
}

/// XSS detection operator (@detectXSS).
pub struct DetectXssOperator;

impl Operator for DetectXssOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        let result = libinjection::detect_xss_bytes(value)?;
        Ok(if result.is_injection {
            ByteOperatorResult::matched(result.fingerprint.unwrap_or_default().into_bytes())
        } else {
            ByteOperatorResult::no_match()
        })
    }

    fn execute(&self, value: &str) -> OperatorResult {
        let result = libinjection::detect_xss(value);
        if result.is_injection {
            OperatorResult::matched(result.fingerprint.unwrap_or_default())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "detectXSS"
    }
}
