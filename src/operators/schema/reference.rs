//! Resolve ordinary references using only the schema documents supplied at load time.
use jsonschema::{uri, Draft, Uri};
use serde_json::Value;
use std::collections::HashMap;
use url::Url;

struct Resource<'a> {
    base: Uri<String>,
    root: &'a Value,
    anchors: HashMap<&'a str, &'a Value>,
}

#[derive(Default)]
pub(super) struct LocalRefs<'a> {
    resources: Vec<Resource<'a>>,
    names: HashMap<String, usize>,
    // The borrowed documents stay immutable and live as long as this index.
    scopes: HashMap<usize, usize>,
}

impl<'a> LocalRefs<'a> {
    pub(super) fn new(root: &'a Value, base: &Url) -> Option<Self> {
        let mut refs = Self::default();
        refs.add_document(root, base)?;
        Some(refs)
    }

    /// Add one already loaded document. Discard the index if this fails.
    pub(super) fn add_document(&mut self, root: &'a Value, base: &Url) -> Option<()> {
        let retrieval = uri::from_str(base.as_str()).ok()?;
        let mut pending = vec![(root, None::<usize>, Draft::default())];
        while let Some((node, parent, inherited_draft)) = pending.pop() {
            let draft = inherited_draft.detect(node);
            if draft == Draft::Unknown || !(node.is_object() || node.is_boolean()) {
                return None;
            }
            let resource = draft.create_resource_ref(node);
            let id = resource.id();
            let scope = match (parent, id) {
                (Some(parent), None) => parent,
                _ => {
                    let base = parent.map_or(&retrieval, |i| &self.resources[i].base);
                    let canonical = match id {
                        Some(id) => uri::resolve_against(&base.borrow(), id).ok()?,
                        None => base.clone(),
                    };
                    // Older drafts can attach a fragment to an absolute resource ID.
                    // Leave this uncommon case to the compiled validator.
                    if canonical.has_fragment() {
                        return None;
                    }
                    let scope = self.resources.len();
                    if self
                        .names
                        .insert(canonical.as_str().into(), scope)
                        .is_some()
                    {
                        return None;
                    }
                    if parent.is_none()
                        && canonical != retrieval
                        && self
                            .names
                            .insert(retrieval.as_str().into(), scope)
                            .is_some()
                    {
                        return None;
                    }
                    self.resources.push(Resource {
                        base: canonical,
                        root: node,
                        anchors: HashMap::new(),
                    });
                    scope
                }
            };
            self.scopes.insert(std::ptr::from_ref(node).addr(), scope);
            let anchor = match draft {
                Draft::Draft202012 | Draft::Draft201909 => {
                    node.get("$anchor").and_then(Value::as_str)
                }
                _ => node
                    .get(draft.id_keyword())
                    .and_then(Value::as_str)
                    .and_then(|s| s.strip_prefix('#')),
            };
            if let Some(name) = anchor {
                if self.resources[scope].anchors.insert(name, node).is_some() {
                    return None;
                }
            }
            // The validator supplies the schema-bearing keywords for each dialect.
            pending.extend(
                draft
                    .subresources_of(node)
                    .map(|child| (child, Some(scope), draft)),
            );
        }
        Some(())
    }

    pub(super) fn resolve(&self, from: &'a Value, reference: &str) -> Option<&'a Value> {
        let current = &self.resources[*self.scopes.get(&std::ptr::from_ref(from).addr())?];
        let (path, fragment) = reference.rsplit_once('#').unwrap_or((reference, ""));
        let resource = if path.is_empty() {
            current
        } else {
            let target = uri::resolve_against(&current.base.borrow(), path).ok()?;
            &self.resources[*self.names.get(target.as_str())?]
        };
        if fragment.is_empty() {
            return Some(resource.root);
        }
        if fragment.starts_with('/') {
            let pointer = percent_encoding::percent_decode_str(fragment)
                .decode_utf8()
                .ok()?;
            let target = resource.root.pointer(&pointer)?;
            return self
                .scopes
                .contains_key(&std::ptr::from_ref(target).addr())
                .then_some(target);
        }
        resource.anchors.get(fragment).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_relative_to_the_containing_resource_and_its_retrieval_alias() {
        let root = json!({"$id":"rules/root.json","$defs":{
            "nested":{"$id":"sub/entry.json","properties":{"tag":{"$anchor":"tag","type":"string"}}},
            "code /~":{"$anchor":"tag","type":"number"}
        }});
        let base = Url::parse("file:///config/original.json").unwrap();
        let refs = LocalRefs::new(&root, &base).unwrap();
        let nested = &root["$defs"]["nested"];
        let tag = &nested["properties"]["tag"];
        let outer = &root["$defs"]["code /~"];
        for (from, reference, target) in [
            (&root, "#", &root),
            (tag, "#", nested),
            (&root, "sub/entry.json#tag", tag),
            (tag, "../root.json#tag", outer),
            (tag, "file:///config/original.json#tag", outer),
            (&root, "#/$defs/code%20~1~0", outer),
        ] {
            assert!(
                std::ptr::eq(refs.resolve(from, reference).unwrap(), target),
                "{reference}"
            );
        }
    }

    #[test]
    fn indexes_only_schema_positions_and_supplied_documents() {
        let root = json!({"const":{"$id":"hidden.json","$anchor":"hidden"}});
        let file = Url::parse("file:///dir/root.json").unwrap();
        let mut refs = LocalRefs::new(&root, &file).unwrap();
        for r in [
            "hidden.json",
            "#hidden",
            "#/const",
            "file:///other.json",
            "https://example.org/",
        ] {
            assert!(refs.resolve(&root, r).is_none(), "{r}");
        }
        let other = json!({"$id":"child/other.json","$anchor":"child","type":"boolean"});
        refs.add_document(&other, &file.join("retrieved.json").unwrap())
            .unwrap();
        assert_eq!(refs.resolve(&root, "retrieved.json#child"), Some(&other));
        assert_eq!(refs.resolve(&other, "../root.json"), Some(&root));
    }

    #[test]
    fn duplicate_resource_names_and_anchors_prevent_ambiguous_resolution() {
        let base = Url::parse("file:///config/root.json").unwrap();
        for duplicate in [
            json!({"$anchor":"duplicate"}),
            json!({"$id":"duplicate.json"}),
        ] {
            let root = json!({"anyOf":[duplicate, duplicate]});
            assert!(LocalRefs::new(&root, &base).is_none());
        }
    }
}
