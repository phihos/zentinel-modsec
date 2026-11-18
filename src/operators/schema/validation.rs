//! JSON Schema validation policy shared by the document and its compiled leaves.
use serde_json::Value;
use std::collections::HashMap;

pub(super) fn validator_options() -> jsonschema::ValidationOptions<'static> {
    jsonschema::options()
        .should_validate_formats(false)
        .with_keyword("uniqueItems", |_, enabled, _| {
            Ok(Box::new(UniqueItems(enabled.as_bool() == Some(true))))
        })
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
