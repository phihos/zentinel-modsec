//! Variable resolution engine.

use super::collection::HashMapCollection;
use super::{RequestData, ResponseData, TxCollection};
use crate::parser::{Selection, VariableName, VariableSpec, XmlTarget};
use std::borrow::Cow;
use std::fmt;

/// The name of one resolved value, kept in parts until someone needs the text.
///
/// Most values a rule resolves never match, so their names are never read.
/// `Display` renders the same text the resolver used to build eagerly:
/// `REQUEST_URI` for a scalar, `ARGS:id` for a collection member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName<'a> {
    collection: &'static str,
    member: Option<Cow<'a, str>>,
}

impl<'a> ResolvedName<'a> {
    fn scalar(name: &'static str) -> Self {
        Self {
            collection: name,
            member: None,
        }
    }

    fn member(collection: &'static str, member: impl Into<Cow<'a, str>>) -> Self {
        Self {
            collection,
            member: Some(member.into()),
        }
    }
}

impl fmt::Display for ResolvedName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.collection)?;
        if let Some(member) = &self.member {
            f.write_str(":")?;
            f.write_str(member)?;
        }
        Ok(())
    }
}

/// One resolved value: its name and its text, borrowed where the request,
/// the response or TX already hold it.
pub type ResolvedValue<'a> = (ResolvedName<'a>, Cow<'a, str>);

/// Hand a scalar variable's single value to `visit`.
fn scalar<'s>(
    visit: &mut impl FnMut(ResolvedName<'s>, Cow<'s, str>),
    name: &'static str,
    value: impl Into<Cow<'s, str>>,
) {
    visit(ResolvedName::scalar(name), value.into());
}

/// Variable resolver for transaction context.
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
        }
    }

    /// Resolve a variable specification to owned name and value pairs.
    pub fn resolve(&self, spec: &VariableSpec) -> Vec<(String, String)> {
        self.resolve_borrowed(spec)
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.into_owned()))
            .collect()
    }

    /// Resolve a variable specification to values without copying them.
    ///
    /// The values borrow from the request, the response and TX; the names
    /// borrow member keys from those and from `spec`. Nothing is formatted or
    /// cloned for a value until a caller asks for it.
    pub fn resolve_borrowed<'s>(&self, spec: &'s VariableSpec) -> Vec<ResolvedValue<'s>>
    where
        'a: 's,
    {
        let mut values = Vec::new();
        self.visit(spec, |name, value| values.push((name, value)));
        values
    }

    /// Hand every value of a variable specification to `visit`, in the order
    /// [`resolve_borrowed`](Self::resolve_borrowed) lists them, without
    /// gathering them first.
    ///
    /// Rule evaluation tests each value as it arrives, so a rule allocates
    /// nothing for the values it only looks at.
    pub fn visit<'s>(
        &self,
        spec: &'s VariableSpec,
        mut visit: impl FnMut(ResolvedName<'s>, Cow<'s, str>),
    ) where
        'a: 's,
    {
        if spec.exclusions.is_empty() {
            self.visit_variable(spec.name, &spec.selection, &mut visit);
        } else {
            self.visit_variable(spec.name, &spec.selection, &mut |name, value| {
                let excluded = spec
                    .exclusions
                    .iter()
                    .any(|e| e.matches(name.collection, name.member.as_deref()));
                if !excluded {
                    visit(name, value);
                }
            });
        }
    }

    /// Visit `TX:key` for a rule whose plan holds the key as `TX` stores it
    /// and its position among the shared variables (see
    /// [`TxCollection::values_at`]). Names the values as
    /// [`visit`](Self::visit) does.
    pub(crate) fn visit_tx_key<'s>(
        &self,
        key: &'s str,
        lowered: &str,
        position: Option<usize>,
        mut visit: impl FnMut(ResolvedName<'s>, Cow<'s, str>),
    ) where
        'a: 's,
    {
        let tx: &'a TxCollection = self.tx;
        keyed(&mut visit, "TX", key, tx.values_at(lowered, position));
    }

    /// Visit `REQUEST_HEADERS:key` for a rule whose plan holds the key as
    /// the headers store it.
    pub(crate) fn visit_header_key<'s>(
        &self,
        key: &'s str,
        lowered: &str,
        mut visit: impl FnMut(ResolvedName<'s>, Cow<'s, str>),
    ) where
        'a: 's,
    {
        let request: &'a RequestData = self.request;
        keyed(
            &mut visit,
            "REQUEST_HEADERS",
            key,
            request.headers.values(lowered),
        );
    }

    /// Visit a variable's values by name.
    fn visit_variable<'s>(
        &self,
        name: VariableName,
        selection: &'s Option<Selection>,
        visit: &mut impl FnMut(ResolvedName<'s>, Cow<'s, str>),
    ) where
        'a: 's,
    {
        let request: &'a RequestData = self.request;
        let response: &'a ResponseData = self.response;
        match name {
            // Request variables
            VariableName::RequestUri => scalar(visit, "REQUEST_URI", &request.uri),
            VariableName::RequestUriRaw => scalar(visit, "REQUEST_URI_RAW", &request.uri_raw),
            VariableName::RequestMethod => scalar(visit, "REQUEST_METHOD", &request.method),
            VariableName::RequestProtocol => scalar(visit, "REQUEST_PROTOCOL", &request.protocol),
            VariableName::QueryString => scalar(visit, "QUERY_STRING", &request.query_string),
            VariableName::RequestFilename => scalar(visit, "REQUEST_FILENAME", &request.path),
            VariableName::RequestLine => {
                // The request line as it arrived. CRS 920100 tests this with a
                // negated regex, so leaving it unresolved made that rule match
                // every request rather than none.
                let uri = if request.uri_raw.is_empty() {
                    &request.uri
                } else {
                    &request.uri_raw
                };
                scalar(
                    visit,
                    "REQUEST_LINE",
                    format!("{} {} {}", request.method, uri, request.protocol),
                )
            }
            VariableName::RequestBasename => {
                // Final path segment. ModSecurity splits on both separators, so
                // a Windows-style path does not hide the basename.
                let basename = self.request.path.rsplit(['/', '\\']).next().unwrap_or("");
                scalar(visit, "REQUEST_BASENAME", basename)
            }
            VariableName::ArgsCombinedSize => {
                let size: usize = [&request.args_get, &request.args_post]
                    .iter()
                    .flat_map(|c| c.iter())
                    .map(|(name, value)| name.len() + value.len())
                    .sum();
                scalar(visit, "ARGS_COMBINED_SIZE", size.to_string())
            }
            // The raw body, always, whichever body processor ran or none.
            // This is why ctl:forceRequestBodyVariable is accepted as a no-op.
            VariableName::RequestBody => scalar(visit, "REQUEST_BODY", request.body_str()),
            VariableName::RequestBodyLength => scalar(
                visit,
                "REQUEST_BODY_LENGTH",
                request.body_length().to_string(),
            ),

            // Collections
            VariableName::Args => {
                for collection in [&request.args_get, &request.args_post] {
                    visit_collection(visit, collection, "ARGS", selection, false);
                }
            }
            VariableName::ArgsGet => {
                visit_collection(visit, &request.args_get, "ARGS_GET", selection, false)
            }
            VariableName::ArgsPost => {
                visit_collection(visit, &request.args_post, "ARGS_POST", selection, false)
            }
            VariableName::ArgsNames => visit_names(
                visit,
                &[&request.args_get, &request.args_post],
                "ARGS_NAMES",
                selection,
            ),
            VariableName::ArgsGetNames => {
                visit_names(visit, &[&request.args_get], "ARGS_GET_NAMES", selection)
            }
            VariableName::ArgsPostNames => {
                visit_names(visit, &[&request.args_post], "ARGS_POST_NAMES", selection)
            }
            VariableName::RequestHeaders => {
                visit_collection(visit, &request.headers, "REQUEST_HEADERS", selection, true)
            }
            VariableName::RequestHeadersNames => visit_names(
                visit,
                &[&request.headers],
                "REQUEST_HEADERS_NAMES",
                selection,
            ),
            VariableName::RequestCookies => {
                visit_collection(visit, &request.cookies, "REQUEST_COOKIES", selection, false)
            }
            VariableName::RequestCookiesNames => visit_names(
                visit,
                &[&request.cookies],
                "REQUEST_COOKIES_NAMES",
                selection,
            ),

            // Multipart body processor results
            VariableName::MultipartPartHeaders => visit_collection(
                visit,
                &request.multipart_part_headers,
                "MULTIPART_PART_HEADERS",
                selection,
                false,
            ),
            VariableName::Files => {
                visit_collection(visit, &request.files, "FILES", selection, false)
            }
            VariableName::FilesNames => {
                visit_names(visit, &[&request.files], "FILES_NAMES", selection)
            }
            VariableName::FilesSizes => {
                visit_collection(visit, &request.files_sizes, "FILES_SIZES", selection, false)
            }
            // Always present -- "0" without uploads -- so a rule comparing the
            // total against a limit, or against 0, finds a value, as in
            // ModSecurity.
            VariableName::FilesCombinedSize => scalar(
                visit,
                "FILES_COMBINED_SIZE",
                request.files_combined_size.to_string(),
            ),
            // Absent while empty, like the default arm.
            VariableName::UniqueId if !request.unique_id.is_empty() => {
                scalar(visit, "UNIQUE_ID", &request.unique_id)
            }
            VariableName::ReqBodyProcessor if !request.body_processor.is_empty() => {
                scalar(visit, "REQBODY_PROCESSOR", &request.body_processor)
            }

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
                let flag = if request.body_error.is_some() {
                    "1"
                } else {
                    "0"
                };
                scalar(visit, "REQBODY_ERROR", flag)
            }
            VariableName::ReqBodyErrorMsg | VariableName::ReqBodyProcessorErrorMsg => {
                if let Some(msg) = &request.body_error {
                    scalar(visit, "REQBODY_ERROR_MSG", msg)
                }
            }

            // Response variables
            VariableName::ResponseStatus => {
                scalar(visit, "RESPONSE_STATUS", response.status.to_string())
            }
            VariableName::ResponseBody => scalar(visit, "RESPONSE_BODY", response.body_str()),
            VariableName::ResponseContentType => {
                scalar(visit, "RESPONSE_CONTENT_TYPE", &response.content_type)
            }
            VariableName::ResponseHeaders => visit_collection(
                visit,
                &response.headers,
                "RESPONSE_HEADERS",
                selection,
                true,
            ),

            // TX collection
            VariableName::Xml => self.visit_xml(selection, visit),

            VariableName::Tx => {
                let tx: &'a TxCollection = self.tx;
                match selection {
                    Some(Selection::Key(key)) => keyed(visit, "TX", key, tx.values(key)),
                    Some(Selection::Regex(pattern)) => members(visit, "TX", tx.iter_regex(pattern)),
                    None => members(visit, "TX", tx.iter()),
                }
            }

            // Client/Server info
            VariableName::RemoteAddr => scalar(visit, "REMOTE_ADDR", &request.client_ip),
            VariableName::RemotePort => {
                scalar(visit, "REMOTE_PORT", request.client_port.to_string())
            }
            VariableName::ServerName => scalar(visit, "SERVER_NAME", &request.server_name),
            VariableName::ServerAddr => scalar(visit, "SERVER_ADDR", &request.server_addr),
            VariableName::ServerPort => {
                scalar(visit, "SERVER_PORT", request.server_port.to_string())
            }

            // Matched variables
            VariableName::MatchedVar => {
                if let Some(v) = self.matched_var {
                    scalar(visit, "MATCHED_VAR", v)
                }
            }
            VariableName::MatchedVars => {
                let matched_vars: &'a [(String, String)] = self.matched_vars;
                members(
                    visit,
                    "MATCHED_VARS",
                    matched_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                );
            }
            VariableName::MatchedVarName => {
                if let Some((name, _)) = self.matched_vars.last() {
                    scalar(visit, "MATCHED_VAR_NAME", name)
                }
            }
            VariableName::MatchedVarsNames => {
                let matched_vars: &'a [(String, String)] = self.matched_vars;
                members(
                    visit,
                    "MATCHED_VARS_NAMES",
                    matched_vars.iter().map(|(k, _)| (k.as_str(), k.as_str())),
                );
            }

            // Default - empty
            _ => {}
        }
    }

    /// Visit an `XML:` target against the flattened XML body.
    ///
    /// The XML body processor flattens element text to `xml.<path>` and
    /// attributes to `xml.<path>.@<name>` in `ARGS`. `XML:/*` and `XML://@*`
    /// are exactly those two sets, so they are answered from the flattening
    /// rather than by evaluating XPath.
    ///
    /// Values are reported under their XPath-style name -- `xml.order.item.@id`
    /// is reported as `XML:/order/item/@id` -- so `%{MATCHED_VAR_NAME}` in a
    /// rule's `logdata` names the node the way the rule addressed it.
    fn visit_xml<'s>(
        &self,
        selection: &Option<Selection>,
        visit: &mut impl FnMut(ResolvedName<'s>, Cow<'s, str>),
    ) where
        'a: 's,
    {
        let Some(target) = XmlTarget::from_selection(selection.as_ref()) else {
            // An XPath expression this engine cannot express. Reported when the
            // rules load, so there is nothing to say per request.
            return;
        };

        let request: &'a RequestData = self.request;
        for (name, value) in request.args_post.iter() {
            let Some(path) = name.strip_prefix("xml.") else {
                continue;
            };
            // An XML element name cannot begin with `@`, so `.@` only ever
            // marks the attribute segment this processor appends.
            let is_attribute = path.contains(".@");
            let wanted = match target {
                XmlTarget::Elements => !is_attribute,
                XmlTarget::Attributes => is_attribute,
                XmlTarget::All => true,
            };
            if wanted {
                visit(
                    ResolvedName::member("XML", format!("/{}", path.replace('.', "/"))),
                    Cow::Borrowed(value),
                );
            }
        }
    }
}

/// Visit a collection's selected values, straight from the collection.
/// `lowercase_key` looks a key selection up case-insensitively (HTTP headers).
fn visit_collection<'s>(
    visit: &mut impl FnMut(ResolvedName<'s>, Cow<'s, str>),
    collection: &'s HashMapCollection,
    prefix: &'static str,
    selection: &'s Option<Selection>,
    lowercase_key: bool,
) {
    match selection {
        Some(Selection::Key(key)) => {
            let lookup = if lowercase_key && key.bytes().any(|b| b.is_ascii_uppercase()) {
                Cow::Owned(key.to_ascii_lowercase())
            } else {
                Cow::Borrowed(key.as_str())
            };
            keyed(visit, prefix, key, collection.values(&lookup));
        }
        Some(Selection::Regex(pattern)) => members(visit, prefix, collection.iter_regex(pattern)),
        None => members(visit, prefix, collection.iter()),
    }
}

/// Visit a `*_NAMES` collection: the values are the keys of the backing
/// collection(s), one entry per stored value (duplicates preserved,
/// matching ModSecurity).
fn visit_names<'s>(
    visit: &mut impl FnMut(ResolvedName<'s>, Cow<'s, str>),
    collections: &[&'s HashMapCollection],
    prefix: &'static str,
    selection: &Option<Selection>,
) {
    for collection in collections {
        for (key, _) in collection.iter() {
            let selected = match selection {
                Some(Selection::Key(sel)) => key.eq_ignore_ascii_case(sel),
                Some(Selection::Regex(pattern)) => pattern.is_match(key),
                None => true,
            };
            if selected {
                visit(ResolvedName::member(prefix, key), Cow::Borrowed(key));
            }
        }
    }
}

/// Visit every `(key, value)` of a collection, named `PREFIX:key`.
fn members<'s>(
    visit: &mut impl FnMut(ResolvedName<'s>, Cow<'s, str>),
    prefix: &'static str,
    entries: impl Iterator<Item = (&'s str, &'s str)>,
) {
    for (k, v) in entries {
        visit(ResolvedName::member(prefix, k), Cow::Borrowed(v));
    }
}

/// Visit every value a `PREFIX:key` selection found, named as the rule wrote
/// the key.
fn keyed<'s>(
    visit: &mut impl FnMut(ResolvedName<'s>, Cow<'s, str>),
    prefix: &'static str,
    key: &'s str,
    values: &'s [String],
) {
    for v in values {
        visit(ResolvedName::member(prefix, key), Cow::Borrowed(v.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::TargetExclusion;

    /// Whether `exclusion` leaves out a value named `key` in its rendered form.
    fn exclusion_matches(key: &str, exclusion: &str) -> bool {
        let e = TargetExclusion::parse(exclusion);
        match key.split_once(':') {
            Some((collection, member)) => e.matches(collection, Some(member)),
            None => e.matches(key, None),
        }
    }

    #[test]
    fn test_invalid_exclusion_regex_excludes_nothing() {
        assert!(!exclusion_matches("ARGS:x", "ARGS:/(unclosed/"));
        assert!(!exclusion_matches("ARGS:(unclosed", "ARGS:/(unclosed/"));
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
        // A keyed exclusion cannot select a scalar variable.
        assert!(!exclusion_matches("ARGS", "ARGS:password"));
    }

    #[test]
    fn test_exclusion_regex_key() {
        // CRS pattern: SecRuleUpdateTargetById 941100 "!REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        assert!(exclusion_matches(
            "REQUEST_COOKIES:_ga_ABC123",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
        assert!(exclusion_matches(
            "REQUEST_COOKIES:_GA",
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
        assert!(exclusion_matches("ARGS", "ARGS"));
        assert!(!exclusion_matches("ARGS_NAMES:anything", "ARGS"));
    }
}
