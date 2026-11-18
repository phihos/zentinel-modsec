//! JSON Schema files are trusted configuration, loaded once with their rule.
mod arena;

use super::{ByteOperatorResult, Operator, OperatorResult};
use crate::{Error, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

pub(crate) struct SchemaOperator {
    validator: jsonschema::Validator,
    inspection_depth: Option<(usize, bool)>,
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
            .with_keyword("uniqueItems", |_, enabled, _| {
                Ok(Box::new(UniqueItems(enabled.as_bool() == Some(true))))
            })
            .with_base_uri(base.as_str())
            .with_retriever(SchemaDirectory(root))
            .should_validate_formats(false)
            .build(&schema)
            .map(|validator| Self {
                validator,
                inspection_depth: inspection_depth(&schema),
            })
            .map_err(|e| error(e.to_string()))
    }
}

// Coraza serializes each item after numeric normalization. That distinguishes
// the sign of zero in uniqueItems, including zeros nested inside an item.
// Other keywords retain the validator's ordinary numeric equality.
struct UniqueItems(bool);

impl<'i> jsonschema::Keyword<'i> for UniqueItems {
    fn is_valid(&self, instance: &'i Value) -> bool {
        let Some(items) = instance.as_array() else {
            return true;
        };
        if !self.0 || jsonschema::json::unique::is_unique(items) {
            return true;
        }
        // Structurally equal items have the same preorder and equal object keys.
        // Within each set of negative-zero positions the built-in equality is exact.
        fn positions(value: &Value, index: &mut usize, out: &mut Vec<usize>) {
            *index += 1;
            match value {
                Value::Number(n)
                    if n.is_f64()
                        && n.as_f64()
                            .is_some_and(|f| f.to_bits() == (-0.0f64).to_bits()) =>
                {
                    out.push(*index)
                }
                Value::Array(a) => a.iter().for_each(|v| positions(v, index, out)),
                Value::Object(o) => {
                    // Cargo feature unification can enable serde_json's preserve_order.
                    let mut entries: Vec<_> = o.iter().collect();
                    entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
                    for (_, v) in entries {
                        positions(v, index, out);
                    }
                }
                _ => {}
            }
        }
        let mut groups = HashMap::<Vec<usize>, Vec<&Value>>::new();
        for item in items {
            let mut zeros = Vec::new();
            positions(item, &mut 0, &mut zeros);
            groups.entry(zeros).or_default().push(item);
        }
        groups
            .values()
            .all(|group| jsonschema::json::unique::is_unique(group))
    }

    fn validate(
        &self,
        instance: &'i Value,
    ) -> std::result::Result<(), jsonschema::ValidationError<'i>> {
        if self.is_valid(instance) {
            Ok(())
        } else {
            Err(jsonschema::ValidationError::custom(
                "array items must be unique",
            ))
        }
    }
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

fn inspection_depth(schema: &Value) -> Option<(usize, bool)> {
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
                "$schema" | "$id" | "id" | "$anchor" | "$dynamicAnchor" | "$comment" | "$defs"
                | "definitions" | "title" | "description" | "examples" | "default" | "type"
                | "format" | "pattern" | "minLength" | "maxLength" | "minimum" | "maximum"
                | "exclusiveMinimum" | "exclusiveMaximum" | "multipleOf" | "readOnly"
                | "writeOnly" | "deprecated" => 0,
                "minProperties" | "maxProperties" | "required" | "dependentRequired"
                | "minItems" | "maxItems" | "minContains" | "maxContains" | "propertyNames" => 1,
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
    (depth < 125).then_some((depth, unique))
}

// Intern exact scalar values and containers of child IDs. Keys in this map
// are at most one container deep, including during hashing, equality and drop.
fn intern_subtree(mut bytes: &[u8], ids: &mut HashMap<Value, usize>) -> Option<usize> {
    let mut frames = Vec::<(Value, Option<String>)>::new();
    while let Some((&byte, rest)) = bytes.split_first() {
        let mut node = match byte {
            b'{' | b'[' => {
                if frames.len() >= 10_000 {
                    return None;
                }
                let container = if byte == b'{' {
                    Value::Object(Default::default())
                } else {
                    Value::Array(Vec::new())
                };
                frames.push((container, None));
                bytes = rest;
                continue;
            }
            b'}' | b']' => {
                bytes = rest;
                frames.pop()?.0
            }
            b':' | b',' | b' ' | b'\t' | b'\n' | b'\r' => {
                bytes = rest;
                continue;
            }
            _ => {
                // The outer RawValue check already validated the grammar. Only
                // scalar tokens reach this decoder, so it never recurses.
                let mut tokens = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
                let value = tokens.next()?.ok()?;
                bytes = &bytes[tokens.byte_offset()..];
                if let Some((Value::Object(_), key @ None)) = frames.last_mut() {
                    *key = Some(value.as_str()?.to_owned());
                    continue;
                }
                value
            }
        };
        // JSON Schema compares numeric values, so 1 and 1.0 are equal.
        if let Value::Number(n) = &node {
            if n.is_f64() {
                let f = n.as_f64()?;
                if f.fract() == 0.0 && f.to_bits() != (-0.0f64).to_bits() {
                    if (0.0..u64::MAX as f64).contains(&f) {
                        node = Value::from(f as u64);
                    } else if (i64::MIN as f64..0.0).contains(&f) {
                        node = Value::from(f as i64);
                    }
                }
            }
        }
        let next = ids.len();
        let id = *ids.entry(node).or_insert(next);
        match frames.last_mut() {
            Some((Value::Array(items), _)) => items.push(Value::from(id)),
            Some((Value::Object(fields), key)) => {
                fields.insert(key.take()?, Value::from(id));
            }
            None => return Some(id),
            _ => unreachable!("frames hold containers"),
        }
    }
    None
}

// RawValue validates the complete grammar iteratively. Keep scalar data and
// visible members unchanged. At the proven cutoff retain each container's
// type and, when uniqueness is checked, its identity. Only the bounded tree reaches recursive
// parsing, the compiled validator, and Value::drop.
fn project_deep_json(input: &[u8], (visible, unique): (usize, bool)) -> Option<serde_json::Value> {
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
                if depth > 10_000 {
                    return None;
                }
                if depth == visible + 1 {
                    omitted_start = raw.len() - bytes.len() - 1;
                    projected
                        .extend_from_slice(&raw.as_bytes()[copy_from..raw.len() - bytes.len()]);
                }
            }
            b'}' | b']' => {
                depth -= 1;
                if depth == visible {
                    copy_from = raw.len() - bytes.len() - 1;
                    if unique {
                        // Replacing children with their structural identity preserves equality
                        // among same-level siblings, even when their only difference is deep.
                        let id = intern_subtree(
                            &raw.as_bytes()[omitted_start..=copy_from],
                            &mut identities,
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

impl Operator for SchemaOperator {
    fn execute_bytes(&self, value: &[u8]) -> Result<ByteOperatorResult> {
        let valid = value.is_empty()
            || match serde_json::from_slice(value) {
                Ok(instance) => self.validator.is_valid(&instance),
                Err(_) => self
                    .inspection_depth
                    .and_then(|depth| project_deep_json(value, depth))
                    .is_some_and(|projected| self.validator.is_valid(&projected)),
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
            let depth = inspection_depth(&schema).unwrap();
            for value in &values {
                let projected =
                    project_deep_json(&serde_json::to_vec(value).unwrap(), depth).unwrap();
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
                project_deep_json(text.as_bytes(), (2, false)).is_some(),
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
            assert_eq!(inspection_depth(&schema), None);
        }
    }
}
