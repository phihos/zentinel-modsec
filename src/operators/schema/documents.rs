//! The two schema compilers share the same configuration-time file contents.
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use url::Url;

// Preserve the retrieval URI even when the document declares a different $id.
pub(super) type SchemaDocuments = BTreeMap<Url, Value>;

#[derive(Clone)]
pub(super) struct SchemaDirectory {
    root: PathBuf,
    documents: Arc<Mutex<Option<SchemaDocuments>>>,
}

impl SchemaDirectory {
    pub(super) fn new(root: PathBuf) -> Self {
        Self {
            root,
            documents: Arc::new(Mutex::new(Some(SchemaDocuments::new()))),
        }
    }

    pub(super) fn finish(self) -> SchemaDocuments {
        self.documents
            .lock()
            .expect("schema directory lock")
            .take()
            .expect("schema compiler has not finished")
    }
}

impl jsonschema::Retrieve for SchemaDirectory {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = Url::parse(uri.as_str())?;
        if url.scheme() != "file" {
            return Err("only local JSON Schema references are supported".into());
        }
        let mut guard = self
            .documents
            .lock()
            .map_err(|_| "schema directory lock failed")?;
        let documents = guard.as_mut().ok_or("schema retrieval has finished")?;
        if let Some(document) = documents.get(&url) {
            return Ok(document.clone());
        }
        let path = url
            .to_file_path()
            .map_err(|_| "only local JSON Schema references are supported")?
            .canonicalize()?;
        if !path.starts_with(&self.root) {
            return Err("schema reference resolves outside the rule directory".into());
        }
        let document: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        documents.insert(url, document.clone());
        Ok(document)
    }
}
