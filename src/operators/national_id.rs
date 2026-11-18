//! Coraza's country-specific national identifier checks.

use super::{ByteOperatorResult, Operator, OperatorResult};
use crate::{Error, Result};

pub(super) struct NationalId {
    candidates: regex::bytes::Regex,
    valid: fn(&[u8]) -> bool,
}

impl NationalId {
    pub(super) fn new(argument: &str) -> Result<Self> {
        let (country, pattern) = argument.split_once(' ').ok_or_else(|| Error::Config {
            message: "@validateNid expects a country code and a regular expression".into(),
        })?;
        let valid = match country {
            "cl" => chile,
            "us" => united_states,
            _ => {
                return Err(Error::Config {
                    message: format!("unsupported @validateNid country {country}"),
                })
            }
        };
        let candidates =
            regex::bytes::Regex::new(pattern).map_err(|source| Error::RegexCompile {
                pattern: pattern.to_owned(),
                source,
            })?;
        Ok(Self { candidates, valid })
    }

    fn evaluate(&self, input: &[u8], capture: bool) -> ByteOperatorResult {
        let mut result = ByteOperatorResult::no_match();
        for (slot, found) in self.candidates.find_iter(input).take(10).enumerate() {
            let candidate = found.as_bytes();
            if !(self.valid)(candidate) {
                continue;
            }
            if !result.matched {
                result = ByteOperatorResult::matched(candidate);
            }
            if !capture {
                break;
            }
            // Coraza indexes by candidate position. Rejected candidates leave
            // holes and preserve any value already present in those TX slots.
            result.captures.resize_with(slot + 1, Vec::new);
            result.captures[slot] = candidate.to_vec();
        }
        result
    }
}

impl Operator for NationalId {
    fn execute(&self, value: &str) -> OperatorResult {
        self.evaluate(value.as_bytes(), true).into_text()
    }

    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        Ok(self.evaluate(value, true))
    }

    fn execute_rule_bytes(&self, value: &[u8], capture: bool) -> Result<ByteOperatorResult> {
        Ok(self.evaluate(value, capture))
    }

    fn supports_capture(&self) -> bool {
        true
    }
    fn name(&self) -> &'static str {
        "validateNid"
    }
}

fn chile(input: &[u8]) -> bool {
    if input.len() < 8 {
        return false;
    }
    let mut digits = input
        .iter()
        .copied()
        .map(|b| b.to_ascii_lowercase())
        .filter(|b| b.is_ascii_digit() || *b == b'k');
    let Some(check_digit) = digits.next_back() else {
        return false;
    };
    let mut number = 0i64;
    for byte in digits {
        if byte == b'k' {
            number = 0;
            break;
        }
        number = number
            .saturating_mul(10)
            .saturating_add(i64::from(byte - b'0'));
    }
    let mut sum = 0;
    let mut weight = 2;
    while number > 0 {
        sum += number % 10 * weight;
        number /= 10;
        weight = if weight == 7 { 2 } else { weight + 1 };
    }
    let expected = match sum % 11 {
        0 => b'0',
        1 => b'k',
        remainder => b'0' + (11 - remainder) as u8,
    };
    check_digit == expected
}

fn united_states(input: &[u8]) -> bool {
    let mut digits = input.iter().copied().filter(u8::is_ascii_digit);
    let mut first = [0; 9];
    for slot in &mut first {
        let Some(digit) = digits.next() else {
            return false;
        };
        *slot = digit;
    }
    let area = &first[..3];
    if area == b"000"
        || area == b"666"
        || area >= b"740"
        || &first[3..5] == b"00"
        || &first[5..] == b"0000"
    {
        return false;
    }

    let mut previous = first[0];
    let mut all_equal = true;
    let mut sequential = true;
    for digit in first[1..].iter().copied().chain(digits) {
        all_equal &= digit == previous;
        sequential &= digit == previous + 1;
        previous = digit;
    }
    !all_equal && !sequential
}
