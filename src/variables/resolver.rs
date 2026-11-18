//! Variable resolution engine.

use super::{ByteValue, RequestData, ResponseData, TxCollection};
#[path = "resolver_bytes.rs"]
mod byte_resolution;
use crate::parser::{Selection, VariableName, VariableSpec, XmlTarget};
pub(crate) use byte_resolution::qualified_name;
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

    /// Resolve a variable by name.
    fn resolve_variable(&self, name: VariableName) -> Vec<(String, String)> {
        match name {
            VariableName::RequestBodyLength => {
                vec![(
                    "REQUEST_BODY_LENGTH".to_string(),
                    self.request.request_body_length_variable(),
                )]
            }
            VariableName::InboundDataError => vec![(
                "INBOUND_DATA_ERROR".into(),
                if self.request.inbound_data_error {
                    "1"
                } else {
                    ""
                }
                .into(),
            )],
            VariableName::OutboundDataError => vec![(
                "OUTBOUND_DATA_ERROR".into(),
                if self.response.outbound_data_error {
                    "1"
                } else {
                    ""
                }
                .into(),
            )],

            VariableName::FilesCombinedSize => vec![(
                "FILES_COMBINED_SIZE".into(),
                self.request.files_combined_size.to_string(),
            )],
            VariableName::MultipartStrictCheck | VariableName::MultipartStrictError => vec![(
                "MULTIPART_STRICT_ERROR".into(),
                if self.request.multipart_strict_error {
                    "1"
                } else {
                    ""
                }
                .into(),
            )],
            VariableName::MultipartDuplicatePartHeader => vec![(
                "MULTIPART_DUPLICATE_PART_HEADER".into(),
                if self.request.multipart_duplicate_part_header {
                    "1"
                } else {
                    "0"
                }
                .into(),
            )],
            VariableName::MultipartInvalidQuoting => vec![(
                "MULTIPART_INVALID_QUOTING".into(),
                if self.request.multipart_invalid_quoting {
                    "1"
                } else {
                    "0"
                }
                .into(),
            )],
            VariableName::ReqBodyProcessor => vec![(
                "REQBODY_PROCESSOR".to_string(),
                self.request.body_processor.clone(),
            )],

            // A body the processor could not handle. These resolved to nothing
            // before, so CRS rule 200002 (`SecRule REQBODY_ERROR "!@eq 0"`)
            // could never fire and a rejected body passed unexamined and
            // unreported.
            //
            // REQBODY_ERROR always has a value -- "0" when the body processed
            // cleanly -- because a rule comparing it against 0 must be able to
            // find it. REQBODY_ERROR_MSG is absent unless there is a message,
            // matching ModSecurity.
            VariableName::ReqBodyError | VariableName::ReqBodyProcessorError => {
                let flag = if self.request.body_error.is_some() {
                    "1"
                } else {
                    "0"
                };
                vec![("REQBODY_ERROR".to_string(), flag.to_string())]
            }
            VariableName::ReqBodyErrorMsg | VariableName::ReqBodyProcessorErrorMsg => {
                match &self.request.body_error {
                    Some(msg) => vec![("REQBODY_ERROR_MSG".to_string(), msg.clone())],
                    None => vec![],
                }
            }

            // Response variables
            VariableName::ResponseProtocol => {
                vec![(
                    "RESPONSE_PROTOCOL".to_string(),
                    self.response.protocol.clone(),
                )]
            }
            VariableName::ResponseStatus => {
                vec![(
                    "RESPONSE_STATUS".to_string(),
                    self.response.status.to_string(),
                )]
            }
            // Client/Server info
            VariableName::RemoteAddr => {
                vec![("REMOTE_ADDR".to_string(), self.request.client_ip.clone())]
            }
            VariableName::RemotePort => {
                vec![(
                    "REMOTE_PORT".to_string(),
                    self.request.client_port.to_string(),
                )]
            }
            VariableName::ServerName => {
                vec![("SERVER_NAME".to_string(), self.request.server_name.clone())]
            }
            VariableName::ServerAddr => {
                vec![("SERVER_ADDR".to_string(), self.request.server_addr.clone())]
            }
            VariableName::ServerPort => {
                vec![(
                    "SERVER_PORT".to_string(),
                    self.request.server_port.to_string(),
                )]
            }

            // Matched variables
            VariableName::MatchedVar => {
                if let Some(v) = self.matched_var {
                    vec![("MATCHED_VAR".to_string(), v.to_string())]
                } else {
                    vec![]
                }
            }
            VariableName::MatchedVarName => match self.matched_vars.last() {
                Some((name, _)) => vec![("MATCHED_VAR_NAME".to_string(), name.clone())],
                None => vec![],
            },
            // Default - empty
            _ => vec![],
        }
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
