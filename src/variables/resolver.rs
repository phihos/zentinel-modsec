//! Variable resolution engine.

use super::{ByteValue, RequestData, ResponseData, TxCollection};
#[path = "resolver_bytes.rs"]
mod byte_resolution;
use crate::parser::{Selection, VariableName, VariableSpec, XmlTarget};
/// Variable resolver for transaction context.
#[derive(Clone, Copy)]
pub struct VariableResolver<'a> {
    request: &'a RequestData,
    response: &'a ResponseData,
    tx: &'a TxCollection,
    matched_var: Option<&'a str>,
    matched_vars: &'a [(String, String)],
    /// Carried alongside the other resolver inputs for symmetry; no variable
    /// reads it yet (`TX:0`..`TX:9` are served from the TX collection).
    #[allow(dead_code)]
    captures: &'a [String],
    matched_bytes: Option<&'a [(ByteValue, ByteValue)]>,
}

impl<'a> VariableResolver<'a> {
    /// Create a new resolver.
    pub fn new(
        request: &'a RequestData,
        response: &'a ResponseData,
        tx: &'a TxCollection,
        matched_var: Option<&'a str>,
        matched_vars: &'a [(String, String)],
        captures: &'a [String],
    ) -> Self {
        Self {
            request,
            response,
            tx,
            matched_var,
            matched_vars,
            captures,
            matched_bytes: None,
        }
    }

    /// Resolve a variable specification to values.
    pub fn resolve(&self, spec: &VariableSpec) -> Vec<(String, String)> {
        self.resolve_bytes(spec)
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_single_variable;

    fn exclusion_matches(name: &str, target: &str) -> bool {
        let (collection, key) = name.split_once(':').unwrap();
        let mut request = RequestData::new();
        let map = if collection == "REQUEST_COOKIES" {
            &mut request.cookies
        } else {
            &mut request.args_get
        };
        map.add(key.into(), "sample".into());
        let mut spec = parse_single_variable(collection).unwrap();
        spec.exclusions.push(target.to_owned());
        let response = ResponseData::new();
        let tx = TxCollection::new();
        VariableResolver::new(&request, &response, &tx, None, &[], &[])
            .resolve(&spec)
            .is_empty()
    }

    #[test]
    fn invalid_regex_exclusion_leaves_the_member_selected() {
        assert!(!exclusion_matches("ARGS:x", "ARGS:/(unclosed/"));
    }

    #[test]
    fn test_exclusion_exact_key() {
        assert!(exclusion_matches("ARGS:password", "ARGS:password"));
        assert!(exclusion_matches("ARGS:Password", "ARGS:password"));
        // Must NOT be a prefix/substring match.
        assert!(!exclusion_matches("ARGS:password2", "ARGS:password"));
        assert!(!exclusion_matches("ARGS:xpassword", "ARGS:password"));
        // Different collection.
        assert!(!exclusion_matches(
            "REQUEST_COOKIES:password",
            "ARGS:password"
        ));
    }

    #[test]
    fn test_exclusion_regex_key() {
        // CRS pattern: SecRuleUpdateTargetById 941100 "!REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        assert!(exclusion_matches(
            "REQUEST_COOKIES:_ga_ABC123",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
        assert!(exclusion_matches(
            "REQUEST_COOKIES:_ga",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
        assert!(!exclusion_matches(
            "REQUEST_COOKIES:session",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
    }

    #[test]
    fn test_exclusion_whole_collection() {
        assert!(exclusion_matches("ARGS:anything", "ARGS"));
        assert!(!exclusion_matches("ARGS_NAMES:anything", "ARGS"));
    }
}
