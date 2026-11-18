//! Lossless resolution used by transaction evaluation.
use super::*;
use crate::variables::{folded_key, ByteValue, HashMapCollection, SelectorPrograms};

pub(crate) fn qualified_name(prefix: &str, member: Option<&[u8]>) -> ByteValue {
    let Some(key) = member.filter(|k| !k.is_empty()) else {
        return prefix.into();
    };
    let mut name = Vec::with_capacity(prefix.len() + 1 + key.len());
    name.extend_from_slice(prefix.as_bytes());
    name.push(b':');
    name.extend_from_slice(key);
    name.into()
}

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

    pub(crate) fn with_selectors(mut self, programs: &'a SelectorPrograms) -> Self {
        self.programs = Some(programs);
        self
    }

    fn matches_regex(&self, pattern: &str, kind: VariableName, key: &[u8]) -> bool {
        self.programs
            .and_then(|p| p.get(pattern, kind))
            .is_some_and(|re| re.is_match(key))
    }

    /// Resolve original value and key bytes, applying exclusions before counts.
    pub fn resolve_bytes(&self, spec: &VariableSpec) -> Vec<(ByteValue, ByteValue)> {
        let mut out = Vec::new();
        let mut append = |prefix: &str, key: Option<&[u8]>, value: &[u8]| {
            out.push((qualified_name(prefix, key), value.into()));
        };
        if self.programs.is_some() {
            self.visit_values(spec, append);
        } else {
            let mut programs = SelectorPrograms::default();
            if let Some(Selection::Regex(pattern)) = &spec.selection {
                programs.add(pattern, spec.name);
            }
            for target in &spec.exclusions {
                if let Some((kind, pattern)) = super::super::selectors::regex_exclusion(target) {
                    programs.add(pattern, kind);
                }
            }
            self.with_selectors(&programs)
                .visit_values(spec, &mut append);
        }
        out
    }

    /// Borrow collection values while filtering. Count rules consume only the
    /// callback cardinality and never allocate names or copies of the values.
    pub(crate) fn visit_values(
        &self,
        spec: &VariableSpec,
        mut visit: impl FnMut(&str, Option<&[u8]>, &[u8]),
    ) {
        let name = spec.name;
        let selection = &spec.selection;
        let request = self.request;
        let mut emit =
            |prefix: &str, canonical: Option<&[u8]>, original: Option<&[u8]>, value: &[u8]| {
                let excluded = spec.exclusions.iter().any(|target| {
                    let (collection, selector) = target
                        .split_once(':')
                        .map_or((target.as_str(), None), |(c, s)| (c, Some(s)));
                    if !collection.eq_ignore_ascii_case(prefix) {
                        return false;
                    }
                    let Some(selector) = selector.filter(|s| !s.is_empty()) else {
                        return true;
                    };
                    let Some(key) = canonical else {
                        return false;
                    };
                    if let Some(pattern) =
                        selector.strip_prefix('/').and_then(|s| s.strip_suffix('/'))
                    {
                        self.matches_regex(pattern, name, key)
                    } else {
                        folded_key(selector.as_bytes()).as_ref() == key
                    }
                });
                if !excluded {
                    visit(prefix, original, value);
                }
            };

        let mut collection = |map: &HashMapCollection,
                              prefix: &str,
                              names: bool,
                              literal: Option<&[u8]>| {
            if map.is_empty() {
                return;
            }
            let selected = match selection {
                // NamedCollectionNames::FindString indexes the existing canonical
                // bucket directly. Rule parsing preserves the case of ARGS names selectors.
                Some(Selection::Key(key))
                    if matches!(
                        name,
                        VariableName::ArgsNames
                            | VariableName::ArgsGetNames
                            | VariableName::ArgsPostNames
                    ) && !key.is_empty() =>
                {
                    Some(std::borrow::Cow::Borrowed(key.as_bytes()))
                }
                Some(Selection::Key(key)) if !key.is_empty() => Some(folded_key(key.as_bytes())),
                _ => None,
            };
            let regex = match selection {
                Some(Selection::Regex(pattern)) if name != VariableName::Xml => {
                    let Some(regex) = self
                        .programs
                        .and_then(|programs| programs.get(pattern, name))
                    else {
                        return;
                    };
                    Some(regex)
                }
                _ => None,
            };
            map.visit(literal.or(selected.as_deref()), |key, original, value| {
                if regex.is_none_or(|re| re.is_match(key)) {
                    emit(
                        prefix,
                        Some(key),
                        Some(original),
                        if names { original } else { value },
                    );
                }
            });
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
            Tx => collection(self.tx.members(), "TX", false, None),
            Xml => match XmlTarget::from_selection(selection.as_ref()) {
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
                    match selection {
                        Some(Selection::Regex(pattern))
                            if !self.matches_regex(pattern, name, &canonical) =>
                        {
                            return
                        }
                        Some(Selection::Key(literal))
                            if !literal.is_empty()
                                && folded_key(literal.as_bytes()) != canonical =>
                        {
                            return
                        }
                        _ => (),
                    }
                    emit(
                        prefix,
                        Some(&canonical),
                        Some(key),
                        if names { key } else { value },
                    );
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
            _ => self.visit_scalar(name, |prefix, value| emit(prefix, None, None, value)),
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
                let mut line = request.method_bytes().to_vec();
                line.push(b' ');
                line.extend_from_slice(request.uri_bytes());
                line.push(b' ');
                line.extend_from_slice(request.protocol_bytes());
                scalar("REQUEST_LINE", &line);
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
            _ => {
                for (key, value) in self.resolve_variable(name) {
                    scalar(&key, value.as_bytes());
                }
            }
        }
    }
}
