//! Variable resolution engine.

use std::sync::OnceLock;

use super::{ByteValue, RequestData, ResponseData, TxCollection};
#[path = "resolver_bytes.rs"]
mod byte_resolution;
use crate::parser::{Selection, VariableName, VariableSpec, XmlTarget};
/// Connector fields distinguish an omitted callback from empty or zero inputs.
#[derive(Clone, Copy, Default)]
pub(crate) struct ConnectorMetadata {
    pub request_line: bool,
    pub client_port: bool,
    pub server_port: bool,
    pub response_status: bool,
    pub source_qualified_arguments: bool,
}

/// Variable resolver for transaction context.
#[derive(Clone, Copy)]
pub struct VariableResolver<'a> {
    request: &'a RequestData,
    response: &'a ResponseData,
    tx: &'a TxCollection,
    matched_var: Option<&'a str>,
    matched_vars: &'a [(String, String)],
    logical_matches: Option<&'a [(ByteValue, ByteValue)]>,
    matched_bytes: Option<&'a [(ByteValue, ByteValue)]>,
    request_line: Option<&'a OnceLock<Box<[u8]>>>,
    connector_metadata: ConnectorMetadata,
}

impl<'a> VariableResolver<'a> {
    /// Create a new resolver.
    pub fn new(
        request: &'a RequestData,
        response: &'a ResponseData,
        tx: &'a TxCollection,
        matched_var: Option<&'a str>,
        matched_vars: &'a [(String, String)],
        _captures: &'a [String],
    ) -> Self {
        Self {
            request,
            response,
            tx,
            matched_var,
            matched_vars,
            logical_matches: None,
            matched_bytes: None,
            request_line: None,
            // Standalone resolver inputs supply their public numeric fields directly.
            connector_metadata: ConnectorMetadata {
                request_line: true,
                client_port: true,
                server_port: true,
                response_status: true,
                source_qualified_arguments: false,
            },
        }
    }

    pub(crate) fn with_request_line(mut self, line: &'a OnceLock<Box<[u8]>>) -> Self {
        self.request_line = Some(line);
        self
    }

    pub(crate) fn with_connector_metadata(mut self, metadata: ConnectorMetadata) -> Self {
        self.connector_metadata = metadata;
        self
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

    #[test]
    fn transaction_clock_uses_local_calendar_and_coraza_formatting() {
        use chrono::{Local, TimeZone};

        let local = Local
            .with_ymd_and_hms(2025, 2, 3, 4, 5, 6)
            .single()
            .unwrap();
        let mut request = RequestData::new();
        request.started = local.into();
        let response = ResponseData::new();
        let tx = TxCollection::new();
        let resolver = VariableResolver::new(&request, &response, &tx, None, &[], &[]);
        let epoch = local.timestamp().to_string();
        for (name, expected) in [
            ("TIME", "04:05:06"),
            ("TIME_HOUR", "04"),
            ("TIME_MIN", "05"),
            ("TIME_SEC", "06"),
            ("TIME_YEAR", "2025"),
            ("TIME_MON", "2"),
            ("TIME_DAY", "3"),
            ("TIME_WDAY", "1"),
            ("TIME_EPOCH", &epoch),
            ("DURATION", "0"),
        ] {
            assert_eq!(
                resolver.resolve(&parse_single_variable(name).unwrap())[0].1,
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn request_line_cache_retains_only_complete_lines_within_its_bound() {
        let response = ResponseData::new();
        let tx = TxCollection::new();
        let spec = parse_single_variable("REQUEST_LINE").unwrap();
        let limit = byte_resolution::MAX_CACHED_REQUEST_LINE;
        for len in [limit - 1, limit, limit + 1] {
            let mut request = RequestData::new();
            request.method = "M".into();
            request.protocol = "P".into();
            request.uri_raw = "x".repeat(len - 4);
            let line = format!("M {} P", request.uri_raw);
            let cache = OnceLock::new();
            for _ in 0..2 {
                let values = VariableResolver::new(&request, &response, &tx, None, &[], &[])
                    .with_request_line(&cache)
                    .resolve(&spec);
                assert_eq!(values[0].1, line);
            }
            assert_eq!(cache.get().is_some(), len <= limit);

            request.uri_raw = "/updated".into();
            let direct = VariableResolver::new(&request, &response, &tx, None, &[], &[]);
            assert_eq!(direct.resolve(&spec)[0].1, "M /updated P");
        }
    }

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
