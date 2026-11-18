//! Resolve ordinary references using only the schema documents supplied at load time.
use jsonschema::{uri, Draft, Uri};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use url::Url;

struct Resource<'a> {
    base: Uri<String>,
    root: &'a Value,
    anchors: HashMap<&'a str, &'a Value>,
    dynamic: Vec<&'a str>,
    recursive: bool,
}

/// Outermost bindings are the only part of the evaluation path that can affect
/// a dynamic reference. Canonicalizing them keeps recursion on a finite graph.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub(super) struct DynamicScope {
    dynamic: BTreeMap<usize, usize>,
    recursive: Option<usize>,
}

#[derive(Default)]
pub(super) struct LocalRefs<'a> {
    default_draft: Draft,
    resources: Vec<Resource<'a>>,
    names: HashMap<String, usize>,
    // Each name has a stable slot and a count of distinct declarations.
    dynamic_names: HashMap<&'a str, (usize, usize)>,
    recursive_roots: usize,
    // The borrowed documents stay immutable and live as long as this index.
    scopes: HashMap<usize, (usize, Draft)>,
}

impl<'a> LocalRefs<'a> {
    pub(super) fn new(root: &'a Value, base: &Url) -> Option<Self> {
        let mut refs = Self {
            default_draft: Draft::default().detect(root),
            ..Self::default()
        };
        refs.add_document(root, base)?;
        Some(refs)
    }

    /// Add one already loaded document. Discard the index if this fails.
    pub(super) fn add_document(&mut self, root: &'a Value, base: &Url) -> Option<()> {
        let retrieval = uri::from_str(base.as_str()).ok()?;
        let mut pending = vec![(root, None::<usize>, self.default_draft)];
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
                    let recursive = draft == Draft::Draft201909
                        && node.get("$recursiveAnchor").and_then(Value::as_bool) == Some(true);
                    self.recursive_roots += usize::from(recursive);
                    self.resources.push(Resource {
                        base: canonical,
                        root: node,
                        anchors: HashMap::new(),
                        dynamic: vec![],
                        recursive,
                    });
                    scope
                }
            };
            self.scopes
                .insert(std::ptr::from_ref(node).addr(), (scope, draft));
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
            if draft == Draft::Draft202012 {
                if let Some(name) = node.get("$dynamicAnchor").and_then(Value::as_str) {
                    if self.resources[scope].anchors.insert(name, node).is_some() {
                        return None;
                    }
                    self.resources[scope].dynamic.push(name);
                    let slot = self.dynamic_names.len();
                    self.dynamic_names.entry(name).or_insert((slot, 0)).1 += 1;
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

    pub(super) fn draft_for(&self, schema: &Value) -> Option<Draft> {
        self.scopes
            .get(&std::ptr::from_ref(schema).addr())
            .map(|&(_, draft)| draft)
    }

    pub(super) fn resolve(&self, from: &'a Value, reference: &str) -> Option<&'a Value> {
        let &(scope, _) = self.scopes.get(&std::ptr::from_ref(from).addr())?;
        let current = &self.resources[scope];
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

    pub(super) fn enter_scope(
        &self,
        parent: &DynamicScope,
        schema: &Value,
    ) -> Option<DynamicScope> {
        let &(idx, _) = self.scopes.get(&std::ptr::from_ref(schema).addr())?;
        let resource = &self.resources[idx];
        let mut scope = parent.clone();
        for name in &resource.dynamic {
            if let Some(&(slot, count)) = self.dynamic_names.get(name) {
                if count > 1 {
                    scope.dynamic.entry(slot).or_insert(idx);
                }
            }
        }
        // A 2019-09 recursive reference walks consecutive anchored resources,
        // stopping at a resource whose root does not declare the recursive anchor.
        if self.recursive_roots > 1 {
            if resource.recursive {
                scope.recursive.get_or_insert(idx);
            } else {
                scope.recursive = None;
            }
        }
        Some(scope)
    }

    pub(super) fn resolve_dynamic_in(
        &self,
        from: &'a Value,
        reference: &str,
        scope: &DynamicScope,
    ) -> Option<&'a Value> {
        let target = self.resolve(from, reference)?;
        let Some((_, name)) = reference.rsplit_once('#') else {
            return Some(target);
        };
        if name.is_empty()
            || name.starts_with('/')
            || self.draft_for(target) != Some(Draft::Draft202012)
            || target.get("$dynamicAnchor").and_then(Value::as_str) != Some(name)
        {
            return Some(target);
        }
        let Some(&(slot, _)) = self.dynamic_names.get(name) else {
            return Some(target);
        };
        match scope.dynamic.get(&slot) {
            Some(&i) => self.resources[i].anchors.get(name).copied(),
            None => Some(target),
        }
    }

    pub(super) fn resolve_recursive_in(
        &self,
        from: &'a Value,
        reference: &str,
        scope: &DynamicScope,
    ) -> Option<&'a Value> {
        if reference != "#" {
            return None;
        }
        let target = self.resolve(from, reference)?;
        if self.draft_for(target) == Some(Draft::Draft201909)
            && target.get("$recursiveAnchor").and_then(Value::as_bool) == Some(true)
        {
            if let Some(idx) = scope.recursive {
                return Some(self.resources[idx].root);
            }
        }
        Some(target)
    }

    pub(super) fn resolve_dynamic(&self, from: &'a Value, reference: &str) -> Option<&'a Value> {
        let target = self.resolve(from, reference)?;
        if let Some((_, name)) = reference.rsplit_once('#') {
            if self.draft_for(target) == Some(Draft::Draft202012)
                && target.get("$dynamicAnchor").and_then(Value::as_str) == Some(name)
                && self
                    .dynamic_names
                    .get(name)
                    .is_some_and(|&(_, count)| count > 1)
            {
                return None;
            }
        }
        Some(target)
    }

    pub(super) fn resolve_recursive(&self, from: &'a Value, reference: &str) -> Option<&'a Value> {
        if reference != "#" {
            return None;
        }
        let target = self.resolve(from, reference)?;
        if self.recursive_roots > 1
            && self.draft_for(target) == Some(Draft::Draft201909)
            && target.get("$recursiveAnchor").and_then(Value::as_bool) == Some(true)
        {
            return None;
        }
        Some(target)
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
    fn dynamic_and_recursive_references_require_scope_invariant_targets() {
        let base = Url::parse("file:///root.json").unwrap();
        let root = json!({"$dynamicAnchor":"node","$recursiveAnchor":true});
        let mut refs = LocalRefs::new(&root, &base).unwrap();
        assert_eq!(refs.resolve_dynamic(&root, "#node"), Some(&root));
        assert_eq!(refs.resolve_recursive(&root, "#"), Some(&root));
        let other = json!({"$dynamicAnchor":"node","$recursiveAnchor":true,"$anchor":"other"});
        refs.add_document(&other, &base.join("other.json").unwrap())
            .unwrap();
        assert!(refs.resolve_dynamic(&root, "#node").is_none());
        assert_eq!(refs.resolve_recursive(&root, "#"), Some(&root));
        assert_eq!(
            refs.resolve_dynamic(&root, "other.json#other"),
            Some(&other)
        );
    }

    #[test]
    fn embedded_dialects_apply_to_their_own_children() {
        let base = Url::parse("file:///root.json").unwrap();
        let root = json!({"$defs":{"child":{"$schema":"http://json-schema.org/draft-07/schema#","$id":"child.json","items":{"type":"number"}}}});
        let refs = LocalRefs::new(&root, &base).unwrap();
        assert_eq!(refs.draft_for(&root), Some(Draft::Draft202012));
        assert_eq!(
            refs.draft_for(&root["$defs"]["child"]["items"]),
            Some(Draft::Draft7)
        );
        assert_eq!(refs.draft_for(&root["$defs"]), None);
    }

    #[test]
    fn dynamic_paths_keep_the_outer_binding_and_coalesce_on_reentry() {
        let base = Url::parse("file:///root.json").unwrap();
        let root = json!({"$dynamicAnchor":"node","$recursiveAnchor":true,"$defs":{
            "tree":{"$id":"tree.json","$recursiveAnchor":true,"$dynamicAnchor":"node","properties":{"next":{"$dynamicRef":"#node"}}}
        }});
        let refs = LocalRefs::new(&root, &base).unwrap();
        let tree = &root["$defs"]["tree"];
        let child = &tree["properties"]["next"];
        let outer = refs.enter_scope(&DynamicScope::default(), &root).unwrap();
        let strict_tree = refs.enter_scope(&outer, tree).unwrap();
        let basic_tree = refs.enter_scope(&DynamicScope::default(), tree).unwrap();
        assert_eq!(strict_tree, outer);
        assert_ne!(basic_tree, outer);
        assert_eq!(refs.enter_scope(&strict_tree, child), Some(outer.clone()));
        assert_eq!(refs.resolve_dynamic_in(child, "#node", &outer), Some(&root));
        assert_eq!(
            refs.resolve_dynamic_in(child, "#node", &basic_tree),
            Some(tree)
        );
        assert_eq!(refs.resolve_recursive_in(child, "#", &outer), Some(tree));
        assert_eq!(refs.resolve(child, "#node"), Some(tree));
    }

    #[test]
    fn recursive_scope_ends_at_a_resource_without_a_draft_2019_recursive_anchor() {
        let base = Url::parse("file:///root.json").unwrap();
        let root = json!({"$schema":"https://json-schema.org/draft/2019-09/schema",
        "$recursiveAnchor":true,"$defs":{
            "bridge":{"$id":"bridge.json","$schema":"https://json-schema.org/draft/2020-12/schema","$recursiveAnchor":true},
            "tree":{"$id":"tree.json","$recursiveAnchor":true}
        }});
        let refs = LocalRefs::new(&root, &base).unwrap();
        let tree = &root["$defs"]["tree"];
        let outer = refs.enter_scope(&DynamicScope::default(), &root).unwrap();
        let inherited = refs.enter_scope(&outer, tree).unwrap();
        assert_eq!(
            refs.resolve_recursive_in(tree, "#", &inherited),
            Some(&root)
        );
        assert!(refs.resolve_recursive(tree, "#").is_none());
        let bridge = refs.enter_scope(&outer, &root["$defs"]["bridge"]).unwrap();
        let fresh = refs.enter_scope(&bridge, tree).unwrap();
        assert_eq!(refs.resolve_recursive_in(tree, "#", &fresh), Some(tree));
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
