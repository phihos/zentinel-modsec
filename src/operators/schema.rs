//! JSON Schema files are trusted configuration, loaded once with their rule.
use super::{ByteOperatorResult, Operator, OperatorResult};
use crate::{Error, Result};
use std::path::{Component, Path, PathBuf};

pub(crate) struct SchemaOperator(jsonschema::Validator);

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
            .map(Self)
            .map_err(|e| error(e.to_string()))
    }
}

impl Operator for SchemaOperator {
    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        let valid = value.is_empty()
            || serde_json::from_slice(value).is_ok_and(|instance| self.0.is_valid(&instance));
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
