//! Lossless resolution used by transaction evaluation.
use super::*;
use crate::variables::{
    folded_key, qualified_name, ByteValue, HashMapCollection, MemberSelector, SelectorPrograms,
    TargetSelection,
};

// Keep at most one common-size request line alive between rule evaluations.
pub(super) const MAX_CACHED_REQUEST_LINE: usize = 4096;

impl<'a> VariableResolver<'a> {
    /// Construct a resolver over original matched-value bytes.
    pub fn new_bytes(
        request: &'a RequestData,
        response: &'a ResponseData,
        tx: &'a TxCollection,
        matched: &'a [(ByteValue, ByteValue)],
    ) -> Self {
        let mut resolver = Self::new(request, response, tx, None, &[], &[]);
        resolver.matched_bytes = Some(matched);
        resolver
    }

    /// Resolve original value and key bytes, applying exclusions before counts.
    pub fn resolve_bytes(&self, spec: &VariableSpec) -> Vec<(ByteValue, ByteValue)> {
        let mut out = Vec::new();
        let mut programs = SelectorPrograms::default();
        if let Some(Selection::Regex(pattern)) = &spec.selection {
            programs.add(pattern, spec.name);
        }
        for target in &spec.exclusions {
            if let Some((kind, pattern)) = super::super::selectors::regex_exclusion(target) {
                programs.add(pattern, kind);
            }
        }
        let selection = TargetSelection::for_lookup(spec, &programs);
        self.visit_values(spec, &selection, |prefix, key, value| {
            out.push((qualified_name(prefix, key), value.into()));
        });
        out
    }

    /// Borrow collection values while filtering. Count rules consume only the
    /// callback cardinality and never allocate names or copies of the values.
    pub(crate) fn visit_values(
        &self,
        spec: &VariableSpec,
        selection: &TargetSelection,
        mut visit: impl FnMut(&str, Option<&[u8]>, &[u8]),
    ) {
        let name = spec.name;
        let request = self.request;
        let mut collection =
            |map: &HashMapCollection, prefix: &str, names: bool, literal: Option<&[u8]>| {
                if map.is_empty() {
                    return;
                }
                let (selected, regex) = match &selection.member {
                    MemberSelector::All => (None, None),
                    MemberSelector::Key(key) => (Some(key.as_ref()), None),
                    MemberSelector::Regex(Some(regex)) | MemberSelector::TxAsciiPrefix(regex) => {
                        (None, Some(regex))
                    }
                    MemberSelector::Regex(None) => return,
                };
                map.visit_filtered(
                    literal.or(selected),
                    |key| regex.is_none_or(|re| re.is_match(key)) && !selection.excludes(Some(key)),
                    |_, original, value| {
                        visit(prefix, Some(original), if names { original } else { value })
                    },
                );
            };

        use VariableName::*;
        match name {
            Args | ArgsNames => {
                let names = name == ArgsNames;
                let prefix = if names { "ARGS_NAMES" } else { "ARGS" };
                collection(&request.args_get, prefix, names, None);
                collection(&request.args_post, prefix, names, None);
            }
            ArgsGet => collection(&request.args_get, "ARGS_GET", false, None),
            ArgsPost => collection(&request.args_post, "ARGS_POST", false, None),
            ArgsGetNames => collection(&request.args_get, "ARGS_GET_NAMES", true, None),
            ArgsPostNames => collection(&request.args_post, "ARGS_POST_NAMES", true, None),
            RequestHeaders => collection(&request.headers, "REQUEST_HEADERS", false, None),
            RequestHeadersNames => {
                collection(&request.headers, "REQUEST_HEADERS_NAMES", true, None)
            }
            ResponseHeaders => collection(&self.response.headers, "RESPONSE_HEADERS", false, None),
            ResponseHeadersNames => {
                collection(&self.response.headers, "RESPONSE_HEADERS_NAMES", true, None)
            }
            RequestCookies => collection(&request.cookies, "REQUEST_COOKIES", false, None),
            RequestCookiesNames => {
                collection(&request.cookies, "REQUEST_COOKIES_NAMES", true, None)
            }
            MultipartPartHeaders => collection(
                &request.multipart_part_headers,
                "MULTIPART_PART_HEADERS",
                false,
                None,
            ),
            Files => collection(&request.files, "FILES", false, None),
            FilesNames => collection(&request.files_names, "FILES_NAMES", false, None),
            FilesSizes => collection(&request.files_sizes, "FILES_SIZES", false, None),
            MultipartName => collection(&request.multipart_names, "MULTIPART_NAME", false, None),
            MultipartFilename => collection(
                &request.multipart_filenames,
                "MULTIPART_FILENAME",
                false,
                None,
            ),
            MultipartFilenameCharset => collection(
                &request.multipart_filename_charsets,
                "MULTIPART_FILENAME_CHARSET",
                false,
                None,
            ),
            MultipartFilenameLanguage => collection(
                &request.multipart_filename_languages,
                "MULTIPART_FILENAME_LANGUAGE",
                false,
                None,
            ),
            Tx => self.tx.visit(&selection.member, |key, value| {
                if !selection.excludes(Some(key)) {
                    visit("TX", Some(key), value);
                }
            }),
            Xml => match XmlTarget::from_selection(spec.selection.as_ref()) {
                Some(XmlTarget::Elements) => collection(&request.xml, "XML", false, Some(b"/*")),
                Some(XmlTarget::Attributes) => {
                    collection(&request.xml, "XML", false, Some(b"//@*"))
                }
                Some(XmlTarget::All) => collection(&request.xml, "XML", false, None),
                None => (),
            },
            MatchedVars | MatchedVarsNames => {
                let names = name == MatchedVarsNames;
                let prefix = if names {
                    "MATCHED_VARS_NAMES"
                } else {
                    "MATCHED_VARS"
                };
                let mut matched = |key: &[u8], value: &[u8]| {
                    let canonical = folded_key(key);
                    if !selection.member.matches(Some(&canonical)) {
                        return;
                    }
                    if !selection.excludes(Some(&canonical)) {
                        visit(prefix, Some(key), if names { key } else { value });
                    }
                };
                if let Some(values) = self.matched_bytes {
                    for (key, value) in values {
                        matched(key.as_bytes(), value.as_bytes());
                    }
                } else {
                    for (key, value) in self.matched_vars {
                        matched(key.as_bytes(), value.as_bytes());
                    }
                }
            }
            _ if !selection.excludes(None) => self.visit_scalar(name, |prefix, value| {
                debug_assert_eq!(prefix, super::super::selectors::emitted_name(name));
                visit(prefix, None, value);
            }),
            _ => (),
        }
    }

    fn visit_scalar(&self, name: VariableName, mut scalar: impl FnMut(&str, &[u8])) {
        let request = self.request;
        use VariableName::*;
        match name {
            RequestUri => scalar("REQUEST_URI", request.uri_bytes()),
            RequestUriRaw => scalar("REQUEST_URI_RAW", request.uri_bytes()),
            RequestFilename => scalar("REQUEST_FILENAME", request.path_bytes()),
            QueryString => scalar("QUERY_STRING", request.query_bytes()),
            RequestMethod => scalar("REQUEST_METHOD", request.method_bytes()),
            RequestProtocol => scalar("REQUEST_PROTOCOL", request.protocol_bytes()),
            RequestBasename => {
                let path = request.path_bytes();
                // Coraza keeps the entire decoded path for a directory target.
                let basename = path
                    .rsplit(|&b| b == b'/' || b == b'\\')
                    .next()
                    .filter(|last| !last.is_empty())
                    .unwrap_or(path);
                scalar("REQUEST_BASENAME", basename);
            }
            RequestLine => {
                if let Some(line) = self.request_line.and_then(OnceLock::get) {
                    return scalar("REQUEST_LINE", line);
                }
                let line = [
                    request.method_bytes(),
                    b" ",
                    request.uri_bytes(),
                    b" ",
                    request.protocol_bytes(),
                ]
                .concat();
                if let Some(cache) = self
                    .request_line
                    .filter(|_| line.len() <= MAX_CACHED_REQUEST_LINE)
                {
                    scalar(
                        "REQUEST_LINE",
                        cache.get_or_init(|| line.into_boxed_slice()),
                    );
                } else {
                    scalar("REQUEST_LINE", &line);
                }
            }
            RequestBody => scalar("REQUEST_BODY", request.request_body_bytes_variable()),
            ResponseBody => scalar("RESPONSE_BODY", self.response.body_variable_bytes()),
            ResponseContentLength => {
                // An inspected empty body exposes "0"; an uninspected body
                // retains the initial empty scalar, even with a length header.
                let length = if self.response.body_inspected {
                    self.response.body_length().to_string()
                } else {
                    String::new()
                };
                scalar("RESPONSE_CONTENT_LENGTH", length.as_bytes());
            }
            ResponseContentType => {
                scalar("RESPONSE_CONTENT_TYPE", self.response.content_type_bytes())
            }
            ArgsCombinedSize => {
                let mut size = 0;
                for map in [&request.args_get, &request.args_post] {
                    map.visit(None, |_, key, value| size += key.len() + value.len());
                }
                scalar("ARGS_COMBINED_SIZE", size.to_string().as_bytes());
            }
            MatchedVar | MatchedVarName if self.matched_bytes.is_some() => {
                if let Some((key, value)) = self.matched_bytes.and_then(|values| values.last()) {
                    if name == MatchedVar {
                        scalar("MATCHED_VAR", value.as_bytes());
                    } else {
                        scalar("MATCHED_VAR_NAME", key.as_bytes());
                    }
                }
            }
            RequestBodyLength => scalar(
                "REQUEST_BODY_LENGTH",
                request.request_body_length_variable().as_bytes(),
            ),
            ArgumentsLimitReached => {
                scalar("ARGUMENTS_LIMIT_REACHED", request.argument_limit_flag())
            }
            InboundDataError => scalar(
                "INBOUND_DATA_ERROR",
                if request.inbound_data_error {
                    b"1"
                } else {
                    b""
                },
            ),
            OutboundDataError => scalar(
                "OUTBOUND_DATA_ERROR",
                if self.response.outbound_data_error {
                    b"1"
                } else {
                    b""
                },
            ),
            FilesCombinedSize => scalar(
                "FILES_COMBINED_SIZE",
                request.files_combined_size.to_string().as_bytes(),
            ),
            MultipartStrictCheck | MultipartStrictError => scalar(
                "MULTIPART_STRICT_ERROR",
                if request.multipart_strict_error {
                    b"1"
                } else {
                    b""
                },
            ),
            MultipartDuplicatePartHeader => scalar(
                "MULTIPART_DUPLICATE_PART_HEADER",
                if request.multipart_duplicate_part_header {
                    b"1"
                } else {
                    b"0"
                },
            ),
            MultipartInvalidQuoting => scalar(
                "MULTIPART_INVALID_QUOTING",
                if request.multipart_invalid_quoting {
                    b"1"
                } else {
                    b"0"
                },
            ),
            ReqBodyProcessor => scalar("REQBODY_PROCESSOR", request.body_processor.as_bytes()),
            // The error flag is always present. The message exists only after a processor error.
            ReqBodyError | ReqBodyProcessorError => scalar(
                "REQBODY_ERROR",
                if request.body_error.is_some() {
                    b"1"
                } else {
                    b"0"
                },
            ),
            ReqBodyErrorMsg | ReqBodyProcessorErrorMsg => {
                if let Some(message) = &request.body_error {
                    scalar("REQBODY_ERROR_MSG", message.as_bytes());
                }
            }
            ResponseProtocol => scalar("RESPONSE_PROTOCOL", self.response.protocol.as_bytes()),
            ResponseStatus => scalar(
                "RESPONSE_STATUS",
                self.response.status.to_string().as_bytes(),
            ),
            RemoteAddr => scalar("REMOTE_ADDR", request.client_ip.as_bytes()),
            RemotePort => scalar("REMOTE_PORT", request.client_port.to_string().as_bytes()),
            ServerName => scalar("SERVER_NAME", request.server_name.as_bytes()),
            ServerAddr => scalar("SERVER_ADDR", request.server_addr.as_bytes()),
            ServerPort => scalar("SERVER_PORT", request.server_port.to_string().as_bytes()),
            MatchedVar => {
                if let Some(value) = self.matched_var {
                    scalar("MATCHED_VAR", value.as_bytes());
                }
            }
            MatchedVarName => {
                if let Some((key, _)) = self.matched_vars.last() {
                    scalar("MATCHED_VAR_NAME", key.as_bytes());
                }
            }
            _ => (),
        }
    }
}
