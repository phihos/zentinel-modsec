//! Bound the instance prefix a finite schema can observe before validation.
use super::arena::{child, intern_subtree, Arena, MAX_DOCUMENT_DEPTH};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Projection {
    pub(super) depth: usize,
    // At the cutoff, uniqueItems still needs to distinguish unequal containers.
    preserve_identity: bool,
}

// A finite schema only looks a finite distance into its instance. Equality can
// distinguish a nonempty container from an empty one at the deepest constant.
fn constant_depth(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(constant_depth).max().unwrap_or(0),
        Value::Array(values) => 1 + values.iter().map(constant_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn has_resource_id(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            ["$id", "id"]
                .iter()
                .any(|key| map.get(*key).is_some_and(Value::is_string))
                || map.values().any(has_resource_id)
        }
        Value::Array(values) => values.iter().any(has_resource_id),
        _ => false,
    }
}

impl Projection {
    pub(super) fn for_schema(schema: &Value) -> Option<Self> {
        fn bound(
            schema: &Value,
            root: Option<&Value>,
            budget: &mut usize,
            steps: usize,
            unique: &mut bool,
        ) -> Option<usize> {
            if schema.is_boolean() {
                return Some(0);
            }
            if steps == 0 {
                return None;
            }
            *budget = budget.checked_sub(1)?;

            let mut depth = 0;
            for (key, value) in schema.as_object()? {
                if key == "uniqueItems" && value == true {
                    *unique = true;
                    depth = depth.max(1);
                    continue;
                }
                let mut child = |value: &Value| bound(value, root, budget, steps - 1, unique);
                let needs = match key.as_str() {
                    "$schema" | "$id" | "id" | "$anchor" | "$dynamicAnchor" | "$comment"
                    | "$defs" | "definitions" | "title" | "description" | "examples"
                    | "default" | "type" | "format" | "pattern" | "minLength" | "maxLength"
                    | "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum"
                    | "multipleOf" | "readOnly" | "writeOnly" | "deprecated"
                    | "contentMediaType" | "contentEncoding" => 0,
                    "minProperties" | "maxProperties" | "required" | "dependentRequired"
                    | "minItems" | "maxItems" | "minContains" | "maxContains" | "propertyNames" => {
                        1
                    }
                    "uniqueItems" if value == false => 0,
                    "properties" | "patternProperties" | "dependentSchemas" => {
                        let mut max = 0;
                        for subschema in value.as_object()?.values() {
                            max = max.max(child(subschema)?);
                        }
                        1 + max
                    }
                    "items" | "prefixItems" | "allOf" | "anyOf" | "oneOf" if value.is_array() => {
                        let mut max = 0;
                        for subschema in value.as_array()? {
                            max = max.max(child(subschema)?);
                        }
                        max + usize::from(matches!(key.as_str(), "items" | "prefixItems"))
                    }
                    "contains"
                    | "items"
                    | "additionalItems"
                    | "additionalProperties"
                    | "unevaluatedItems"
                    | "unevaluatedProperties" => 1 + child(value)?,
                    "not" | "if" | "then" | "else" => child(value)?,
                    "const" => constant_depth(value),
                    "enum" => value
                        .as_array()?
                        .iter()
                        .map(constant_depth)
                        .max()
                        .unwrap_or(0),
                    // Resolve only ordinary same-document JSON Pointers. A document
                    // with resource IDs can change a reference's base beneath us.
                    "$ref" => {
                        let pointer = value.as_str()?.strip_prefix('#')?;
                        if !pointer.starts_with('/')
                            || !pointer
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"/$_-~.".contains(&b))
                        {
                            return None;
                        }
                        child(root?.pointer(pointer)?)?
                    }
                    _ => return None,
                };
                depth = depth.max(needs);
            }
            Some(depth)
        }
        // The graph of references can be cyclic or expand exponentially. Reaching
        // either analysis budget just keeps the normal validation path.
        let local_root = (!has_resource_id(schema)).then_some(schema);
        let mut unique = false;
        let depth = bound(schema, local_root, &mut 1024, 64, &mut unique)?;
        (depth < 125).then_some(Self {
            depth,
            preserve_identity: unique,
        })
    }

    // Only rebuild the bounded prefix from arena nodes. Compilation limits
    // this recursion independently of how deeply the request is nested.
    pub(super) fn project_node(self, arena: &Arena, id: usize) -> Value {
        let project_child = |value| {
            Self {
                depth: self.depth - 1,
                ..self
            }
            .project_node(arena, child(value))
        };
        match &arena.nodes()[id] {
            Value::Array(items) if self.depth > 0 => {
                Value::Array(items.iter().map(project_child).collect())
            }
            Value::Object(fields) if self.depth > 0 => Value::Object(
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), project_child(value)))
                    .collect(),
            ),
            Value::Array(_) => Value::Array(if self.preserve_identity {
                vec![id.into()]
            } else {
                vec![]
            }),
            Value::Object(_) => {
                let mut object = serde_json::Map::new();
                if self.preserve_identity {
                    object.insert(String::new(), id.into());
                }
                Value::Object(object)
            }
            scalar => scalar.clone(),
        }
    }

    // RawValue validates the complete grammar iteratively. Keep scalar data and
    // visible members unchanged. At the proven cutoff retain each container's
    // type and, when uniqueness is checked, its identity. Only the bounded tree reaches recursive
    // parsing, the compiled validator, and Value::drop.
    pub(super) fn project_json(self, input: &[u8]) -> Option<Value> {
        let raw = serde_json::from_slice::<&serde_json::value::RawValue>(input)
            .ok()?
            .get();
        let mut bytes = raw.as_bytes();
        let mut projected = Vec::new();
        let mut identities = HashMap::new();
        let mut omitted_start = 0;
        let mut copy_from = 0;
        let mut depth = 0usize;
        while let Some((&byte, rest)) = bytes.split_first() {
            bytes = rest;
            match byte {
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_DOCUMENT_DEPTH {
                        return None;
                    }
                    if depth == self.depth + 1 {
                        omitted_start = raw.len() - bytes.len() - 1;
                        projected
                            .extend_from_slice(&raw.as_bytes()[copy_from..raw.len() - bytes.len()]);
                    }
                }
                b'}' | b']' => {
                    depth -= 1;
                    if depth == self.depth {
                        copy_from = raw.len() - bytes.len() - 1;
                        if self.preserve_identity {
                            // Replacing children with their structural identity preserves equality
                            // among same-level siblings, even when their only difference is deep.
                            let id = intern_subtree(
                                &raw.as_bytes()[omitted_start..=copy_from],
                                &mut identities,
                                None,
                            )?;
                            if byte == b'}' {
                                projected.extend_from_slice(br#""":"#);
                            }
                            projected.extend_from_slice(id.to_string().as_bytes());
                        }
                    }
                }
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
                    let offset = raw.len() - bytes.len() - 1;
                    if !raw[offset..offset + len + 1]
                        .parse::<f64>()
                        .is_ok_and(f64::is_finite)
                    {
                        return None;
                    }
                    bytes = &bytes[len..];
                }
                _ => (),
            }
        }
        projected.extend_from_slice(&raw.as_bytes()[copy_from..]);
        serde_json::from_slice(&projected).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn projection_preserves_compiled_schema_decisions() {
        let items = json!({"type":"string", "minLength": 2});
        let pair = json!({"type":"array","minItems":1,"items":items});
        let mut values = vec![
            json!(null),
            json!(false),
            json!(0),
            json!(1.5),
            json!(""),
            json!("ab"),
            json!([]),
            json!({}),
        ];
        for _ in 0..3 {
            let children = values.clone();
            for v in children {
                values.extend([
                    json!([v]),
                    json!([v, [1]]),
                    json!({"p":v}),
                    json!({"p":v,"q":{"v":2}}),
                ]);
            }
        }
        let schemas = [
            json!({"type":"array","uniqueItems":true}),
            json!({"type":"array"}),
            json!({"type":"object","minProperties":1}),
            json!({"properties":{"p":pair},"additionalProperties":false}),
            json!({"patternProperties":{"^p":items},"maxProperties":1}),
            json!({"allOf":[{"required":["p"]},{"properties":{"p":{"not":pair}}}]}),
            json!({"if":{"required":["p"]},"then":{"properties":{"p":items}},"else":false}),
            json!({"dependentSchemas":{"p":{"required":["q"]}}}),
            json!({"dependentRequired":{"p":["q"]}}),
            json!({"prefixItems":[pair],"items":false}),
            json!({"contains":pair,"minContains":1,"maxContains":2}),
            json!({"oneOf":[pair,{"not":{"type":"array"}}]}),
            json!({"enum":[{"p":[]},{"p":{"q":{}}},[[],[1]]]}),
            json!({"const":{"p":{"q":[]}}}),
            json!({"$defs":{"entry":pair},"properties":{"p":{"$ref":"#/$defs/entry"}}}),
            json!({"properties":{"p":true},"unevaluatedProperties":{"type":"array","items":items}}),
        ];
        for schema in schemas {
            let validator = jsonschema::validator_for(&schema).unwrap();
            let projection = Projection::for_schema(&schema).unwrap();
            for value in &values {
                let projected = projection
                    .project_json(&serde_json::to_vec(value).unwrap())
                    .unwrap();
                assert_eq!(
                    validator.is_valid(&projected),
                    validator.is_valid(value),
                    "{schema} {value}"
                );
            }
        }
    }

    #[test]
    fn projection_applies_the_document_depth_limit_before_validation() {
        for (levels, valid) in [
            (127, true),
            (128, true),
            (129, true),
            (10_000, true),
            (10_001, false),
        ] {
            let text = format!("{}42{}", "[".repeat(levels), "]".repeat(levels));
            assert_eq!(
                Projection {
                    depth: 2,
                    preserve_identity: false
                }
                .project_json(text.as_bytes())
                .is_some(),
                valid,
                "{levels}"
            );
        }
    }

    #[test]
    fn unbounded_inspection_does_not_use_a_projection() {
        for schema in [
            json!({"$ref":"#/$defs/list","$defs":{"list":{"items":{"$ref":"#/$defs/list"}}}}),
            json!({"$id":"https://example.invalid/schema","$ref":"#/$defs/body","$defs":{"body":true}}),
            json!({"$dynamicRef":"#node"}),
            json!({"properties":{"node":{"$ref":"child.json"}}}),
        ] {
            assert_eq!(Projection::for_schema(&schema), None);
        }
    }
}
