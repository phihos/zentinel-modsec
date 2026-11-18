//! JSON Schema files are trusted configuration, loaded once with their rule.
use super::{ByteOperatorResult, Operator, OperatorResult};
use crate::{Error, Result};
use std::path::{Component, Path, PathBuf};

pub(crate) struct SchemaOperator {
    validator: jsonschema::Validator,
    accepts_any: bool,
}

// Pin retrieval to the configuration directory. This overrides any network/file
// resolver an embedding application might enable through Cargo feature unification.
struct SchemaDirectory(PathBuf);
impl jsonschema::Retrieve for SchemaDirectory {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> std::result::Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = url::Url::parse(uri.as_str())?;
        let path = url
            .to_file_path()
            .map_err(|_| "only local JSON Schema references are supported")?;
        let path = path.canonicalize()?;
        if !path.starts_with(&self.0) {
            return Err("schema reference resolves outside the rule directory".into());
        }
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
}

impl SchemaOperator {
    pub(crate) fn load(argument: &str, root: &Path) -> Result<Self> {
        let path = Path::new(argument);
        let error = |message: String| Error::Config {
            message: format!("@validateSchema {argument}: {message}"),
        };
        if !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            || !path
                .components()
                .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
        {
            return Err(error(
                "expected a relative .json file under the rule directory".into(),
            ));
        }
        let root = root.canonicalize().map_err(|e| error(e.to_string()))?;
        let file = root
            .join(path)
            .canonicalize()
            .map_err(|e| error(e.to_string()))?;
        if !file.starts_with(&root) {
            return Err(error(
                "schema file resolves outside the rule directory".into(),
            ));
        }
        let base = url::Url::from_file_path(&file)
            .map_err(|_| error("invalid schema file path".into()))?;
        let bytes = std::fs::read(file).map_err(|e| error(e.to_string()))?;
        let schema: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| error(e.to_string()))?;
        jsonschema::options()
            .with_base_uri(base.as_str())
            .with_retriever(SchemaDirectory(root))
            .should_validate_formats(false)
            .build(&schema)
            .map(|validator| Self {
                validator,
                accepts_any: schema == true
                    || schema.as_object().is_some_and(|object| object.is_empty()),
            })
            .map_err(|e| error(e.to_string()))
    }
}

// RawValue checks JSON syntax using an iterative scanner. For an unconstrained
// schema we need no recursive Value tree. Match Go's nested-container limit and
// its requirement that numbers fit a float64 when decoding an untyped instance.
fn valid_untyped_json(input: &[u8]) -> bool {
    let Ok(raw) = serde_json::from_slice::<&serde_json::value::RawValue>(input) else {
        return false;
    };
    let mut bytes = raw.get().as_bytes();
    let mut depth = 0;
    while let Some((&byte, rest)) = bytes.split_first() {
        bytes = rest;
        match byte {
            b'{' | b'[' => {
                depth += 1;
                if depth > 10_000 {
                    return false;
                }
            }
            b'}' | b']' => depth -= 1,
            b'"' => loop {
                let end = memchr::memchr2(b'"', b'\\', bytes).expect("validated JSON string");
                let escaped = bytes[end] == b'\\';
                bytes = &bytes[end + 1 + usize::from(escaped)..];
                if !escaped {
                    break;
                }
            },
            b'-' | b'0'..=b'9' => {
                let len = bytes
                    .iter()
                    .take_while(|b| matches!(b, b'0'..=b'9' | b'.' | b'E' | b'e' | b'+' | b'-'))
                    .count();
                let offset = raw.get().len() - bytes.len() - 1;
                if !raw.get()[offset..offset + len + 1]
                    .parse::<f64>()
                    .is_ok_and(f64::is_finite)
                {
                    return false;
                }
                bytes = &bytes[len..];
            }
            _ => (),
        }
    }
    true
}

impl Operator for SchemaOperator {
    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        let valid = value.is_empty()
            || match serde_json::from_slice(value) {
                Ok(instance) => self.validator.is_valid(&instance),
                Err(_) if self.accepts_any => valid_untyped_json(value),
                Err(_) => false,
            };
        Ok(if valid {
            ByteOperatorResult::no_match()
        } else {
            ByteOperatorResult::matched(value)
        })
    }

    fn execute(&self, value: &str) -> OperatorResult {
        self.execute_bytes(value.as_bytes())
            .expect("infallible schema evaluation")
            .into_text()
    }

    fn name(&self) -> &'static str {
        "validateSchema"
    }
}
