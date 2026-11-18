//! Runtime operator arguments can themselves contain captured arbitrary bytes.
use super::*;

/// Compile a runtime argument without formatting binary macros for display.
pub fn compile_operator_bytes(spec: &OperatorSpec, argument: &[u8]) -> Result<Arc<dyn Operator>> {
    match spec.name {
        OperatorName::Eq => return Ok(Arc::new(EqOperator::from_expanded(argument))),
        OperatorName::Gt => return Ok(Arc::new(GtOperator::from_expanded(argument))),
        OperatorName::Ge => return Ok(Arc::new(GeOperator::from_expanded(argument))),
        OperatorName::Lt => return Ok(Arc::new(LtOperator::from_expanded(argument))),
        OperatorName::Le => return Ok(Arc::new(LeOperator::from_expanded(argument))),
        OperatorName::ContainsWord => {
            return Ok(Arc::new(comparison::ContainsWordOperator::new(argument)))
        }
        OperatorName::Within => {
            return Ok(Arc::new(WithinOperator {
                haystack: argument.to_vec(),
            }))
        }
        _ => {}
    }
    if let Ok(argument) = std::str::from_utf8(argument) {
        return compile_operator(&OperatorSpec {
            name: spec.name,
            negated: spec.negated,
            argument: argument.into(),
        });
    }
    match spec.name {
        OperatorName::Rx => {
            let mut pattern = String::new();
            use std::fmt::Write;
            for &byte in argument {
                if byte.is_ascii() {
                    pattern.push(char::from(byte));
                } else {
                    write!(pattern, "\\x{byte:02x}").expect("String write");
                }
            }
            Ok(Arc::new(RxOperator::new(&pattern)?))
        }
        OperatorName::Pm => Ok(Arc::new(PmOperator::from_patterns(
            argument
                .split(u8::is_ascii_whitespace)
                .filter(|s| !s.is_empty()),
        )?)),
        OperatorName::Contains
        | OperatorName::StrMatch
        | OperatorName::BeginsWith
        | OperatorName::EndsWith
        | OperatorName::StreQ
        | OperatorName::Ne => Ok(Arc::new(ByteArgument {
            kind: spec.name,
            argument: argument.to_vec(),
        })),
        _ => Err(crate::Error::UnsupportedBinaryInput {
            component: format!("{:?} operator argument", spec.name),
        }),
    }
}

struct ByteArgument {
    kind: OperatorName,
    argument: Vec<u8>,
}
impl Operator for ByteArgument {
    fn execute(&self, value: &str) -> OperatorResult {
        self.execute_bytes(value.as_bytes())
            .expect("byte comparison is infallible")
            .into_text()
    }
    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        let matched = match self.kind {
            OperatorName::Contains | OperatorName::StrMatch => {
                self.argument.is_empty()
                    || value
                        .windows(self.argument.len())
                        .any(|part| part == self.argument)
            }
            OperatorName::BeginsWith => value.starts_with(&self.argument),
            OperatorName::EndsWith => value.ends_with(&self.argument),
            OperatorName::StreQ => value == self.argument,
            OperatorName::Ne => value != self.argument,
            _ => unreachable!("only byte-argument comparisons are constructed"),
        };
        Ok(if matched {
            let portion = match self.kind {
                OperatorName::Contains
                | OperatorName::StrMatch
                | OperatorName::BeginsWith
                | OperatorName::EndsWith => self.argument.clone(),
                _ => value.to_vec(),
            };
            ByteOperatorResult::matched(portion)
        } else {
            ByteOperatorResult::no_match()
        })
    }
    fn name(&self) -> &'static str {
        "byteArgument"
    }
}
