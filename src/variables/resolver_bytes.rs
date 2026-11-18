//! Lossless resolution used by transaction evaluation.
use super::*;
use crate::variables::{
    folded_key, qualified_name, ByteValue, HashMapCollection, MemberSelector, SelectorPrograms,
    TargetSelection,
};
use std::borrow::Cow;

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
    // Keep the general collection traversal out of the compiled phase loop.
    #[inline(never)]
    pub(crate) fn visit_values(
        &self,
        spec: &VariableSpec,
        selection: &TargetSelection,
        mut visit: impl FnMut(&str, Option<&[u8]>, &[u8]),
    ) {
        let name = spec.name;
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
        if self.visit_collection_maps(name, |map, prefix, names| {
            collection(map, prefix, names, None);
        }) {
            return;
        }

        match name {
            Tx => self.tx.visit(&selection.member, |key, value| {
                if !selection.excludes(Some(key)) {
                    visit("TX", Some(key), value);
                }
            }),
            Xml => match XmlTarget::from_selection(spec.selection.as_ref()) {
                Some(XmlTarget::Elements) => {
                    collection(&self.request.xml, "XML", false, Some(b"/*"))
                }
                Some(XmlTarget::Attributes) => {
                    collection(&self.request.xml, "XML", false, Some(b"//@*"))
                }
                Some(XmlTarget::All) => collection(&self.request.xml, "XML", false, None),
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
            _ if !selection.excludes(None) => {
                if let Some(value) = self.scalar_value(name) {
                    visit(super::super::selectors::emitted_name(name), None, &value);
                }
            }
            _ => (),
        }
    }

    /// Visit the backing maps in lookup order. A recognized collection may be
    /// empty until its body processor has run.
    fn visit_collection_maps(
        &self,
        name: VariableName,
        mut visit: impl FnMut(&'a HashMapCollection, &'static str, bool),
    ) -> bool {
        use VariableName::*;
        let request = self.request;
        match name {
            Args | ArgsNames => {
                let names = name == ArgsNames;
                let prefix = if names { "ARGS_NAMES" } else { "ARGS" };
                visit(&request.args_get, prefix, names);
                visit(&request.args_post, prefix, names);
                if let Some(path) = request.path_arguments() {
                    visit(path, prefix, names);
                }
            }
            ArgsPath => {
                if let Some(path) = request.path_arguments() {
                    visit(path, "ARGS_PATH", false);
                }
            }
            ArgsGet => visit(&request.args_get, "ARGS_GET", false),
            ArgsPost => visit(&request.args_post, "ARGS_POST", false),
            ArgsGetNames => visit(&request.args_get, "ARGS_GET_NAMES", true),
            ArgsPostNames => visit(&request.args_post, "ARGS_POST_NAMES", true),
            RequestHeaders => visit(&request.headers, "REQUEST_HEADERS", false),
            RequestHeadersNames => visit(&request.headers, "REQUEST_HEADERS_NAMES", true),
            ResponseHeaders => visit(&self.response.headers, "RESPONSE_HEADERS", false),
            ResponseArgs => {
                if let Some(json) = &self.response.json {
                    visit(&json.args, "RESPONSE_ARGS", false);
                }
            }
            ResponseHeadersNames => visit(&self.response.headers, "RESPONSE_HEADERS_NAMES", true),
            RequestCookies => visit(&request.cookies, "REQUEST_COOKIES", false),
            RequestCookiesNames => visit(&request.cookies, "REQUEST_COOKIES_NAMES", true),
            MultipartPartHeaders => visit(
                &request.multipart_part_headers,
                "MULTIPART_PART_HEADERS",
                false,
            ),
            Files => visit(&request.files, "FILES", false),
            FilesNames => visit(&request.files_names, "FILES_NAMES", false),
            FilesTmpnames => {
                if let Some(files) = &request.uploads {
                    visit(&files.names, "FILES_TMPNAMES", false);
                }
            }
            FilesSizes => visit(&request.files_sizes, "FILES_SIZES", false),
            MultipartName => visit(&request.multipart_names, "MULTIPART_NAME", false),
            MultipartFilename => visit(&request.multipart_filenames, "MULTIPART_FILENAME", false),
            MultipartFilenameCharset => visit(
                &request.multipart_filename_charsets,
                "MULTIPART_FILENAME_CHARSET",
                false,
            ),
            MultipartFilenameLanguage => visit(
                &request.multipart_filename_languages,
                "MULTIPART_FILENAME_LANGUAGE",
                false,
            ),
            _ => return false,
        }
        true
    }

    /// Keyed macros read values, including for collections whose rule targets
    /// enumerate names. A missing collection key expands to the original token.
    pub(crate) fn macro_value(
        &self,
        name: VariableName,
        key: &[u8],
        token: &'a [u8],
    ) -> Cow<'a, [u8]> {
        use VariableName::*;
        let key = if matches!(name, ResponseHeaders | ResponseHeadersNames) {
            folded_key(key)
        } else {
            Cow::Borrowed(key)
        };
        let mut value = None;
        if !self.visit_collection_maps(name, |map, _, _| {
            if value.is_none() {
                value = map.first_value_bytes(&key);
            }
        }) {
            value = match name {
                Xml => self.request.xml.first_value_bytes(&key),
                MatchedVars | MatchedVarsNames => self
                    .matched_bytes
                    .and_then(|values| {
                        values
                            .iter()
                            .find(|(k, _)| k.as_bytes().eq_ignore_ascii_case(&key))
                    })
                    .map(|(_, v)| v.as_bytes()),
                _ => return self.scalar_value(name).unwrap_or(Cow::Borrowed(b"")),
            };
        }
        Cow::Borrowed(value.unwrap_or(token))
    }

    fn scalar_value(&self, name: VariableName) -> Option<Cow<'a, [u8]>> {
        let request = self.request;
        let response = self.response;
        use VariableName::*;
        let bytes: &[u8] = match name {
            UniqueId => request.unique_id().as_bytes(),
            RequestUri | RequestUriRaw => request.uri_bytes(),
            RequestFilename => request.path_bytes(),
            QueryString => request.query_bytes(),
            RequestMethod => request.method_bytes(),
            RequestProtocol => request.protocol_bytes(),
            RequestBasename => {
                let path = request.path_bytes();
                // Coraza keeps the entire decoded path for a directory target.
                path.rsplit(|&b| b == b'/' || b == b'\\')
                    .next()
                    .filter(|last| !last.is_empty())
                    .unwrap_or(path)
            }
            RequestLine if !self.connector_metadata.request_line => b"",
            RequestLine => {
                if let Some(line) = self.request_line.and_then(OnceLock::get) {
                    return Some(Cow::Borrowed(line));
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
                    cache.get_or_init(|| line.into_boxed_slice())
                } else {
                    return Some(Cow::Owned(line));
                }
            }
            RequestBody => request.request_body_bytes_variable(),
            ResBodyProcessor => {
                if response.json.is_some() {
                    b"JSON"
                } else {
                    b""
                }
            }
            ResBodyError | ResBodyProcessorError | ResBodyErrorMsg | ResBodyProcessorErrorMsg => {
                let error = response
                    .json
                    .as_ref()
                    .and_then(|json| json.error.as_deref());
                match (name, error) {
                    (_, None) => b"",
                    (ResBodyErrorMsg, Some(error)) => {
                        return Some(Cow::Owned(format!("JSON: {error}").into_bytes()))
                    }
                    (ResBodyProcessorErrorMsg, Some(error)) => error.as_bytes(),
                    _ => b"1",
                }
            }
            ResponseBody => response.body_variable_bytes(),
            // An inspected empty body exposes "0"; an uninspected body retains
            // its initial empty scalar, even with a length header.
            ResponseContentLength if response.body_inspected && response.json.is_none() => {
                return Some(Cow::Owned(response.body_length().to_string().into_bytes()));
            }
            ResponseContentLength => b"",
            ResponseContentType => response.content_type_bytes(),
            ArgsCombinedSize => {
                let mut size = 0;
                for map in [&request.args_get, &request.args_post] {
                    map.visit(None, |_, key, value| size += key.len() + value.len());
                }
                return Some(Cow::Owned(size.to_string().into_bytes()));
            }
            MatchedVar | MatchedVarName if self.matched_bytes.is_some() => {
                let (key, value) = self.matched_bytes?.last()?;
                if name == MatchedVar {
                    value.as_bytes()
                } else {
                    key.as_bytes()
                }
            }
            RequestBodyLength => {
                return Some(Cow::Owned(
                    request.request_body_length_variable().into_bytes(),
                ))
            }
            ArgumentsLimitReached => request.argument_limit_flag(),
            InboundDataError => {
                if request.inbound_data_error {
                    b"1"
                } else {
                    b""
                }
            }
            OutboundDataError => {
                if response.outbound_data_error {
                    b"1"
                } else {
                    b"0"
                }
            }
            FilesCombinedSize => {
                return Some(Cow::Owned(
                    request.files_combined_size.to_string().into_bytes(),
                ))
            }
            MultipartStrictCheck | MultipartStrictError => {
                if request.multipart_strict_error {
                    b"1"
                } else {
                    b""
                }
            }
            MultipartDuplicatePartHeader => {
                if request.multipart_duplicate_part_header {
                    b"1"
                } else {
                    b"0"
                }
            }
            MultipartInvalidQuoting => {
                if request.multipart_invalid_quoting {
                    b"1"
                } else {
                    b"0"
                }
            }
            ReqBodyProcessor => request.body_processor.as_bytes(),
            ReqBodyError | ReqBodyProcessorError => {
                if request.body_error.is_some() {
                    b"1"
                } else {
                    b"0"
                }
            }
            ReqBodyErrorMsg | ReqBodyProcessorErrorMsg => request.body_error.as_deref()?.as_bytes(),
            ResponseProtocol => response.protocol.as_bytes(),
            ResponseStatus if !self.connector_metadata.response_status => b"",
            ResponseStatus => return Some(Cow::Owned(response.status.to_string().into_bytes())),
            RemoteAddr => request.client_ip.as_bytes(),
            RemotePort if !self.connector_metadata.client_port => b"",
            RemotePort => return Some(Cow::Owned(request.client_port.to_string().into_bytes())),
            ServerName => request.server_name.as_bytes(),
            ServerAddr => request.server_addr.as_bytes(),
            ServerPort if !self.connector_metadata.server_port => b"",
            ServerPort => return Some(Cow::Owned(request.server_port.to_string().into_bytes())),
            MatchedVar => self.matched_var?.as_bytes(),
            MatchedVarName => self.matched_vars.last()?.0.as_bytes(),
            _ => return None,
        };
        Some(Cow::Borrowed(bytes))
    }
}
