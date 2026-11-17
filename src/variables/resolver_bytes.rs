//! Lossless resolution used by transaction evaluation.
use super::*;
use crate::variables::{ByteCollection, ByteValue};

pub(crate) fn cached_bytes_regex(
    pattern: &str,
    collection: VariableName,
) -> Option<regex::bytes::Regex> {
    static CACHE: Lazy<RwLock<HashMap<String, Option<regex::bytes::Regex>>>> =
        Lazy::new(Default::default);
    let pattern = if collection == VariableName::Tx {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    };
    if let Some(hit) = CACHE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&pattern)
    {
        return hit.clone();
    }
    let compiled = regex::bytes::Regex::new(&pattern).ok();
    CACHE
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .entry(pattern)
        .or_insert(compiled)
        .clone()
}

fn named(prefix: &str, key: &[u8]) -> ByteValue {
    if key.is_empty() {
        return ByteValue::from(prefix);
    }
    let mut name = prefix.as_bytes().to_vec();
    name.push(b':');
    name.extend_from_slice(key);
    ByteValue::from(name)
}
fn collection_values(
    collection: &dyn ByteCollection,
    prefix: &str,
    selection: &Option<Selection>,
    kind: VariableName,
    names: bool,
) -> Vec<(ByteValue, ByteValue)> {
    let literal = match selection {
        Some(Selection::Key(key)) => Some(key.as_bytes()),
        _ => None,
    };
    let regex = match selection {
        Some(Selection::Regex(pattern)) => cached_bytes_regex(pattern, kind),
        _ => None,
    };
    if matches!(selection, Some(Selection::Regex(_))) && regex.is_none() {
        return vec![];
    }
    collection
        .all_bytes()
        .into_iter()
        .filter(|(key, _)| {
            if let Some(literal) = literal {
                if names
                    || matches!(
                        kind,
                        VariableName::Tx
                            | VariableName::RequestHeaders
                            | VariableName::ResponseHeaders
                    )
                {
                    key.eq_ignore_ascii_case(literal)
                } else {
                    *key == literal
                }
            } else {
                regex.as_ref().is_none_or(|regex| regex.is_match(key))
            }
        })
        .map(|(key, value)| {
            (
                named(prefix, key),
                ByteValue::from(if names { key } else { value }),
            )
        })
        .collect()
}

fn excluded(key: &[u8], exclusion: &str) -> bool {
    let (collection, member) = key
        .iter()
        .position(|&b| b == b':')
        .map_or((key, &b""[..]), |i| (&key[..i], &key[i + 1..]));
    match exclusion.split_once(':') {
        Some((wanted, selection)) => {
            if !collection.eq_ignore_ascii_case(wanted.as_bytes()) {
                return false;
            }
            if selection.starts_with('/') && selection.ends_with('/') && selection.len() >= 2 {
                cached_bytes_regex(
                    &selection[1..selection.len() - 1],
                    if collection.eq_ignore_ascii_case(b"TX") {
                        VariableName::Tx
                    } else {
                        VariableName::Args
                    },
                )
                .is_some_and(|re| re.is_match(member))
            } else {
                member.eq_ignore_ascii_case(selection.as_bytes())
            }
        }
        None => collection.eq_ignore_ascii_case(exclusion.as_bytes()),
    }
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

    /// Resolve original value and key bytes, applying exclusions before counts.
    pub fn resolve_bytes(&self, spec: &VariableSpec) -> Vec<(ByteValue, ByteValue)> {
        self.resolve_bytes_inner(spec.name, &spec.selection)
            .into_iter()
            .filter(|(name, _)| {
                !spec
                    .exclusions
                    .iter()
                    .any(|exclusion| excluded(name.as_bytes(), exclusion))
            })
            .collect()
    }

    fn resolve_bytes_inner(
        &self,
        name: VariableName,
        selection: &Option<Selection>,
    ) -> Vec<(ByteValue, ByteValue)> {
        let scalar =
            |name: &str, value: &[u8]| vec![(ByteValue::from(name), ByteValue::from(value))];
        let request = self.request;
        let collection = |value: &dyn ByteCollection, prefix: &str, names: bool| {
            collection_values(value, prefix, selection, name, names)
        };
        match name {
            VariableName::Args => {
                let mut values = collection(&request.args_get, "ARGS", false);
                values.extend(collection(&request.args_post, "ARGS", false));
                values
            }
            VariableName::ArgsGet => collection(&request.args_get, "ARGS_GET", false),
            VariableName::ArgsPost => collection(&request.args_post, "ARGS_POST", false),
            VariableName::ArgsNames => {
                let mut values = collection(&request.args_get, "ARGS_NAMES", true);
                values.extend(collection(&request.args_post, "ARGS_NAMES", true));
                values
            }
            VariableName::ArgsGetNames => collection(&request.args_get, "ARGS_GET_NAMES", true),
            VariableName::ArgsPostNames => collection(&request.args_post, "ARGS_POST_NAMES", true),
            VariableName::RequestHeaders => collection(&request.headers, "REQUEST_HEADERS", false),
            VariableName::RequestHeadersNames => {
                collection(&request.headers, "REQUEST_HEADERS_NAMES", true)
            }
            VariableName::RequestCookies => collection(&request.cookies, "REQUEST_COOKIES", false),
            VariableName::RequestCookiesNames => {
                collection(&request.cookies, "REQUEST_COOKIES_NAMES", true)
            }
            VariableName::MultipartPartHeaders => collection(
                &request.multipart_part_headers,
                "MULTIPART_PART_HEADERS",
                false,
            ),
            VariableName::Files => collection(&request.files, "FILES", false),
            VariableName::FilesNames => collection(&request.files_names, "FILES_NAMES", false),
            VariableName::FilesSizes => collection(&request.files_sizes, "FILES_SIZES", false),
            VariableName::MultipartName => {
                collection(&request.multipart_names, "MULTIPART_NAME", false)
            }
            VariableName::MultipartFilename => {
                collection(&request.multipart_filenames, "MULTIPART_FILENAME", false)
            }
            VariableName::MultipartFilenameCharset => collection(
                &request.multipart_filename_charsets,
                "MULTIPART_FILENAME_CHARSET",
                false,
            ),
            VariableName::MultipartFilenameLanguage => collection(
                &request.multipart_filename_languages,
                "MULTIPART_FILENAME_LANGUAGE",
                false,
            ),
            VariableName::Tx => collection(self.tx, "TX", false),
            VariableName::Xml => match XmlTarget::from_selection(selection.as_ref()) {
                Some(XmlTarget::Elements) => collection_values(
                    &request.xml,
                    "XML",
                    &Some(Selection::Key("/*".into())),
                    name,
                    false,
                ),
                Some(XmlTarget::Attributes) => collection_values(
                    &request.xml,
                    "XML",
                    &Some(Selection::Key("//@*".into())),
                    name,
                    false,
                ),
                Some(XmlTarget::All) => collection(&request.xml, "XML", false),
                None => vec![],
            },
            VariableName::RequestUri => scalar("REQUEST_URI", request.uri_bytes()),
            VariableName::RequestUriRaw => scalar("REQUEST_URI_RAW", request.uri_bytes()),
            VariableName::RequestFilename => scalar("REQUEST_FILENAME", request.path_bytes()),
            VariableName::QueryString => scalar("QUERY_STRING", request.query_bytes()),
            VariableName::RequestMethod => scalar("REQUEST_METHOD", request.method_bytes()),
            VariableName::RequestProtocol => scalar("REQUEST_PROTOCOL", request.protocol_bytes()),
            VariableName::RequestBasename => scalar(
                "REQUEST_BASENAME",
                request
                    .path_bytes()
                    .rsplit(|&b| b == b'/' || b == b'\\')
                    .next()
                    .unwrap_or_default(),
            ),
            VariableName::RequestLine => {
                let mut line = request.method_bytes().to_vec();
                line.push(b' ');
                line.extend_from_slice(request.uri_bytes());
                line.push(b' ');
                line.extend_from_slice(request.protocol_bytes());
                scalar("REQUEST_LINE", &line)
            }
            VariableName::RequestBody => {
                scalar("REQUEST_BODY", request.request_body_bytes_variable())
            }
            VariableName::ResponseBody => scalar("RESPONSE_BODY", &self.response.body),
            VariableName::ResponseHeaders => {
                collection(&self.response.headers, "RESPONSE_HEADERS", false)
            }
            VariableName::ResponseContentType => scalar(
                "RESPONSE_CONTENT_TYPE",
                self.response
                    .headers
                    .get_bytes(b"content-type")
                    .and_then(|values| values.first().copied())
                    .unwrap_or_default(),
            ),
            VariableName::ArgsCombinedSize => {
                let size: usize = request
                    .args_get
                    .all_bytes()
                    .into_iter()
                    .chain(request.args_post.all_bytes())
                    .map(|(k, v)| k.len() + v.len())
                    .sum();
                scalar("ARGS_COMBINED_SIZE", size.to_string().as_bytes())
            }
            VariableName::MatchedVar
            | VariableName::MatchedVarName
            | VariableName::MatchedVars
            | VariableName::MatchedVarsNames => {
                let Some(values) = self.matched_bytes else {
                    return self
                        .resolve_variable(name, selection)
                        .into_iter()
                        .map(|(k, v)| (k.into(), v.into()))
                        .collect();
                };
                match name {
                    VariableName::MatchedVar => values
                        .last()
                        .map_or_else(Vec::new, |(_, v)| scalar("MATCHED_VAR", v.as_bytes())),
                    VariableName::MatchedVarName => values
                        .last()
                        .map_or_else(Vec::new, |(k, _)| scalar("MATCHED_VAR_NAME", k.as_bytes())),
                    VariableName::MatchedVars => values
                        .iter()
                        .map(|(k, v)| (named("MATCHED_VARS", k.as_bytes()), v.clone()))
                        .collect(),
                    _ => values
                        .iter()
                        .map(|(k, _)| (named("MATCHED_VARS_NAMES", k.as_bytes()), k.clone()))
                        .collect(),
                }
            }
            _ => self
                .resolve_variable(name, selection)
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }
}
