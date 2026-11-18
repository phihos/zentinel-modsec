//! JSON Schema files are trusted configuration, loaded once with their rule.
mod arena;
mod documents;
mod projection;
mod recursive;
mod reference;
mod validation;

use super::{ByteOperatorResult, Operator, OperatorResult};
use crate::{Error, Result};
use documents::SchemaDirectory;
use projection::Projection;
use std::path::{Component, Path};
use validation::validator_options;

pub(crate) struct SchemaOperator {
    validator: jsonschema::Validator,
    deep: DeepValidation,
}

// A projection is sufficient when a schema only inspects a bounded prefix.
// Recursive references need a compiled program or cannot evaluate deep input.
enum DeepValidation {
    Project(Projection),
    Recursive(recursive::Program),
    Unsupported,
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
        let directory = SchemaDirectory::new(root);
        validator_options()
            .with_base_uri(base.as_str())
            .with_retriever(directory.clone())
            .build(&schema)
            .map(|validator| {
                let documents = directory.finish();
                let deep = if let Some(projection) = Projection::for_schema(&schema) {
                    DeepValidation::Project(projection)
                } else if let Some(program) =
                    recursive::Program::compile(&schema, &base, &documents, validator.draft())
                {
                    DeepValidation::Recursive(program)
                } else {
                    DeepValidation::Unsupported
                };
                Self { validator, deep }
            })
            .map_err(|e| error(e.to_string()))
    }
}

impl Operator for SchemaOperator {
    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        let valid = value.is_empty()
            || match serde_json::from_slice(value) {
                Ok(instance) => self.validator.is_valid(&instance),
                Err(_) => match &self.deep {
                    DeepValidation::Project(projection) => projection
                        .project_json(value)
                        .is_some_and(|projected| self.validator.is_valid(&projected)),
                    DeepValidation::Recursive(program) => program.is_valid(value),
                    DeepValidation::Unsupported => false,
                },
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
