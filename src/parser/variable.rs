//! Variable parsing for SecRule.
//!
//! Optimized with perfect hash function for O(1) variable name lookup.

use crate::error::{Error, Result};
use phf::phf_map;

/// A variable specification in a SecRule.
#[derive(Debug, Clone)]
pub struct VariableSpec {
    /// The variable name.
    pub name: VariableName,
    /// Optional selection (e.g., ARGS:foo or ARGS:/^user/).
    pub selection: Option<Selection>,
    /// Count mode (& prefix).
    pub count_mode: bool,
    /// Exclusions (e.g., !ARGS:foo).
    pub exclusions: Vec<String>,
}

/// Selection mode for collection variables.
#[derive(Debug, Clone)]
pub enum Selection {
    /// Static key selection (ARGS:foo).
    Key(String),
    /// Regex key selection (ARGS:/^user/).
    Regex(String),
}

/// Variable names supported by ModSecurity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VariableName {
    // Request variables
    /// `ARGS`
    Args,
    /// `ARGS_GET`
    ArgsGet,
    /// `ARGS_PATH`
    ArgsPath,
    /// `ARGS_POST`
    ArgsPost,
    /// `ARGS_NAMES`
    ArgsNames,
    /// `ARGS_GET_NAMES`
    ArgsGetNames,
    /// `ARGS_POST_NAMES`
    ArgsPostNames,
    /// `ARGS_COMBINED_SIZE`
    ArgsCombinedSize,
    /// `REQUEST_URI`
    RequestUri,
    /// `REQUEST_URI_RAW`
    RequestUriRaw,
    /// `REQUEST_FILENAME`
    RequestFilename,
    /// `REQUEST_BASENAME`
    RequestBasename,
    /// `REQUEST_LINE`
    RequestLine,
    /// `REQUEST_METHOD`
    RequestMethod,
    /// `REQUEST_PROTOCOL`
    RequestProtocol,
    /// `REQUEST_HEADERS`
    RequestHeaders,
    /// `REQUEST_HEADERS_NAMES`
    RequestHeadersNames,
    /// `REQUEST_COOKIES`
    RequestCookies,
    /// `REQUEST_COOKIES_NAMES`
    RequestCookiesNames,
    /// `REQUEST_BODY`
    RequestBody,
    /// `REQUEST_BODY_LENGTH`
    RequestBodyLength,
    /// `ARGUMENTS_LIMIT_REACHED`
    ArgumentsLimitReached,
    /// `INBOUND_DATA_ERROR`
    InboundDataError,
    /// `OUTBOUND_DATA_ERROR`
    OutboundDataError,
    /// `QUERY_STRING`
    QueryString,

    // Response variables
    /// `RESPONSE_STATUS`
    ResponseStatus,
    /// `RESPONSE_PROTOCOL`
    ResponseProtocol,
    /// `RESPONSE_HEADERS`
    ResponseHeaders,
    /// `RESPONSE_HEADERS_NAMES`
    ResponseHeadersNames,
    /// `RESPONSE_ARGS`
    ResponseArgs,
    /// `RES_BODY_PROCESSOR`
    ResBodyProcessor,
    /// `RES_BODY_ERROR`
    ResBodyError,
    /// `RES_BODY_ERROR_MSG`
    ResBodyErrorMsg,
    /// `RES_BODY_PROCESSOR_ERROR`
    ResBodyProcessorError,
    /// `RES_BODY_PROCESSOR_ERROR_MSG`
    ResBodyProcessorErrorMsg,
    /// `RESPONSE_BODY`
    ResponseBody,
    /// `RESPONSE_CONTENT_TYPE`
    ResponseContentType,
    /// `RESPONSE_CONTENT_LENGTH`
    ResponseContentLength,

    // Server/Client info
    /// `REMOTE_ADDR`
    RemoteAddr,
    /// `REMOTE_PORT`
    RemotePort,
    /// `REMOTE_HOST`
    RemoteHost,
    /// `REMOTE_USER`
    RemoteUser,
    /// `SERVER_ADDR`
    ServerAddr,
    /// `SERVER_PORT`
    ServerPort,
    /// `SERVER_NAME`
    ServerName,

    // Collections
    /// `TX`
    Tx,
    /// `SESSION`
    Session,
    /// `ENV`
    Env,
    /// `IP`
    Ip,
    /// `GLOBAL`
    Global,
    /// `RESOURCE`
    Resource,
    /// `USER`
    User,
    /// `GEO`
    Geo,

    // Matched data
    /// `MATCHED_VAR`
    MatchedVar,
    /// `MATCHED_VARS`
    MatchedVars,
    /// `MATCHED_VAR_NAME`
    MatchedVarName,
    /// `MATCHED_VARS_NAMES`
    MatchedVarsNames,

    // Time variables
    /// `TIME`
    Time,
    /// `TIME_EPOCH`
    TimeEpoch,
    /// `TIME_DAY`
    TimeDay,
    /// `TIME_HOUR`
    TimeHour,
    /// `TIME_MIN`
    TimeMin,
    /// `TIME_SEC`
    TimeSec,
    /// `TIME_WDAY`
    TimeWday,
    /// `TIME_MON`
    TimeMon,
    /// `TIME_YEAR`
    TimeYear,

    // Files
    /// `FILES`
    Files,
    /// `FILES_SIZES`
    FilesSizes,
    /// `FILES_TMPNAMES`
    FilesTmpnames,
    /// `FILES_COMBINED_SIZE`
    FilesCombinedSize,
    /// `FILES_NAMES`
    FilesNames,

    // Special
    /// `UNIQUE_ID`
    UniqueId,
    /// `INBOUND_ANOMALY_SCORE` — running inbound anomaly total.
    InboundAnomalyScore,
    /// `OUTBOUND_ANOMALY_SCORE` — running outbound anomaly total.
    OutboundAnomalyScore,
    /// `DURATION`
    Duration,
    /// `MULTIPART_BOUNDARY_QUOTED` — the multipart boundary was quoted.
    MultipartBoundaryQuoted,
    /// `MULTIPART_BOUNDARY_WHITESPACE` — whitespace surrounded the boundary.
    MultipartBoundaryWhitespace,
    /// `MULTIPART_DATA_AFTER` — content followed the terminating boundary.
    MultipartDataAfter,
    /// `MULTIPART_DATA_BEFORE` — content preceded the first boundary.
    MultipartDataBefore,
    /// `MULTIPART_FILE_LIMIT_EXCEEDED` — more files than the configured limit.
    MultipartFileLimitExceeded,
    /// `MULTIPART_HEADER_FOLDING` — a part header used line folding.
    MultipartHeaderFolding,
    /// `MULTIPART_INVALID_HEADER_FOLDING` — malformed header folding.
    MultipartInvalidHeaderFolding,
    /// `MULTIPART_INVALID_PART` — a part could not be parsed.
    MultipartInvalidPart,
    /// `MULTIPART_INVALID_QUOTING` — malformed quoting in a part header.
    MultipartInvalidQuoting,
    /// `MULTIPART_LF_LINE` — a line ended with LF rather than CRLF.
    MultipartLfLine,
    /// `MULTIPART_MISSING_SEMICOLON` — a part header omitted a semicolon.
    MultipartMissingSemicolon,
    /// `MULTIPART_STRICT_ERROR` — any of the strict multipart checks failed.
    MultipartStrictError,
    /// `MULTIPART_UNMATCHED_BOUNDARY` — a boundary did not match the declared one.
    MultipartUnmatchedBoundary,
    /// `MULTIPART_PART_HEADERS`
    MultipartPartHeaders,
    /// Multipart part names, keyed by part name.
    MultipartName,
    /// Primary and alternative multipart filenames.
    MultipartFilename,
    /// Extended filename charset.
    MultipartFilenameCharset,
    /// Extended filename language.
    MultipartFilenameLanguage,
    /// Duplicate header or conflicting parameter flag.
    MultipartDuplicatePartHeader,

    // XML
    /// `XML`
    Xml,

    // Web server
    /// `WEBSERVER_ERROR_LOG` — messages the web server logged for this transaction.
    WebserverErrorLog,
    /// `HIGHEST_SEVERITY`
    HighestSeverity,
    /// `STATUS_LINE`
    StatusLine,
    /// `FULL_REQUEST`
    FullRequest,
    /// `FULL_REQUEST_LENGTH`
    FullRequestLength,

    // Auth
    /// `AUTH_TYPE`
    AuthType,

    // Request body processing
    /// `REQBODY_PROCESSOR`
    ReqBodyProcessor,
    /// `REQBODY_ERROR`
    ReqBodyError,
    /// `REQBODY_ERROR_MSG`
    ReqBodyErrorMsg,
    /// `REQBODY_PROCESSOR_ERROR`
    ReqBodyProcessorError,
    /// `REQBODY_PROCESSOR_ERROR_MSG`
    ReqBodyProcessorErrorMsg,

    // Multipart strict
    /// `MULTIPART_STRICT_ERROR`
    MultipartStrictCheck,
}

/// Which XML value collection an `XML:` selector refers to.
///
/// The two selectors in the pinned CRS rules -- `XML:/*` for text and
/// `XML://@*` for attribute values -- read dedicated XML collections, without
/// introducing synthetic HTTP arguments or requiring a general XPath engine.
/// Other XPath expressions are reported when rules load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlTarget {
    /// `XML:/*` -- element text.
    Elements,
    /// `XML://@*` -- attribute values.
    Attributes,
    /// A bare `XML` with no selector: everything extracted from the body.
    All,
}

impl XmlTarget {
    /// Interpret an `XML:` selector, or `None` if this engine cannot express it.
    pub fn from_selection(selection: Option<&Selection>) -> Option<Self> {
        match selection {
            None => Some(XmlTarget::All),
            Some(Selection::Key(sel)) => match sel.trim() {
                "/*" => Some(XmlTarget::Elements),
                "//@*" => Some(XmlTarget::Attributes),
                _ => None,
            },
            // `XML:/foo/` parses as a regex selection because of the
            // delimiters, but an XPath expression is not a key regex.
            Some(Selection::Regex(_)) => None,
        }
    }
}

impl VariableName {
    /// Whether the resolver can produce a value for this variable.
    ///
    /// A variable the parser accepts but the resolver has no arm for silently
    /// resolves to nothing, which makes a rule targeting it dead. Callers use
    /// this to say so at load time instead of leaving it to be discovered from
    /// traffic. The match is deliberately exhaustive: a new variant will not
    /// compile until it has been classified here.
    pub fn is_implemented(&self) -> bool {
        match self {
            VariableName::Xml
            | VariableName::Args
            | VariableName::ArgsGet
            | VariableName::ArgsPath
            | VariableName::ArgsPost
            | VariableName::ArgsNames
            | VariableName::ArgsGetNames
            | VariableName::ArgsPostNames
            | VariableName::ArgsCombinedSize
            | VariableName::RequestUri
            | VariableName::RequestUriRaw
            | VariableName::RequestFilename
            | VariableName::RequestBasename
            | VariableName::UniqueId
            | VariableName::Time
            | VariableName::TimeEpoch
            | VariableName::TimeDay
            | VariableName::TimeHour
            | VariableName::TimeMin
            | VariableName::TimeSec
            | VariableName::TimeWday
            | VariableName::TimeMon
            | VariableName::TimeYear
            | VariableName::Duration
            | VariableName::RequestLine
            | VariableName::RequestMethod
            | VariableName::RequestProtocol
            | VariableName::RequestHeaders
            | VariableName::RequestHeadersNames
            | VariableName::RequestCookies
            | VariableName::RequestCookiesNames
            | VariableName::RequestBody
            | VariableName::RequestBodyLength
            | VariableName::ArgumentsLimitReached
            | VariableName::InboundDataError
            | VariableName::OutboundDataError
            | VariableName::QueryString
            | VariableName::ResponseStatus
            | VariableName::ResponseProtocol
            | VariableName::ResponseHeaders
            | VariableName::ResponseHeadersNames
            | VariableName::ResponseArgs
            | VariableName::ResBodyProcessor
            | VariableName::ResBodyError
            | VariableName::ResBodyErrorMsg
            | VariableName::ResBodyProcessorError
            | VariableName::ResBodyProcessorErrorMsg
            | VariableName::ResponseBody
            | VariableName::ResponseContentType
            | VariableName::ResponseContentLength
            | VariableName::RemoteAddr
            | VariableName::RemotePort
            | VariableName::ServerAddr
            | VariableName::ServerPort
            | VariableName::ServerName
            | VariableName::Tx
            | VariableName::MatchedVar
            | VariableName::MatchedVars
            | VariableName::MatchedVarName
            | VariableName::MatchedVarsNames
            | VariableName::Files
            | VariableName::FilesNames
            | VariableName::FilesSizes
            | VariableName::FilesTmpnames
            | VariableName::FilesCombinedSize
            | VariableName::MultipartStrictCheck
            | VariableName::MultipartStrictError
            | VariableName::MultipartInvalidQuoting
            | VariableName::MultipartName
            | VariableName::MultipartFilename
            | VariableName::MultipartFilenameCharset
            | VariableName::MultipartFilenameLanguage
            | VariableName::MultipartDuplicatePartHeader
            | VariableName::MultipartPartHeaders
            | VariableName::ReqBodyProcessor
            | VariableName::ReqBodyError
            | VariableName::ReqBodyErrorMsg
            | VariableName::ReqBodyProcessorError
            | VariableName::ReqBodyProcessorErrorMsg => true,

            VariableName::RemoteHost
            | VariableName::RemoteUser
            | VariableName::Session
            | VariableName::Env
            | VariableName::Ip
            | VariableName::Global
            | VariableName::Resource
            | VariableName::User
            | VariableName::Geo
            | VariableName::InboundAnomalyScore
            | VariableName::OutboundAnomalyScore
            | VariableName::MultipartBoundaryQuoted
            | VariableName::MultipartBoundaryWhitespace
            | VariableName::MultipartDataAfter
            | VariableName::MultipartDataBefore
            | VariableName::MultipartFileLimitExceeded
            | VariableName::MultipartHeaderFolding
            | VariableName::MultipartInvalidHeaderFolding
            | VariableName::MultipartInvalidPart
            | VariableName::MultipartLfLine
            | VariableName::MultipartMissingSemicolon
            | VariableName::MultipartUnmatchedBoundary
            | VariableName::WebserverErrorLog
            | VariableName::HighestSeverity
            | VariableName::StatusLine
            | VariableName::FullRequest
            | VariableName::FullRequestLength
            | VariableName::AuthType => false,
        }
    }
}

// The parser and match-data reporting use the same SecLang spellings.
macro_rules! variable_names {
    ($($label:literal => VariableName::$variant:ident),* $(,)?) => {
        static VARIABLE_MAP: phf::Map<&'static str, VariableName> = phf_map! {
            $($label => VariableName::$variant),*
        };
        impl VariableName {
            pub(crate) fn seclang_name(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)*
                    // Variants accessible through the typed API only.
                    Self::InboundAnomalyScore => "INBOUND_ANOMALY_SCORE",
                    Self::OutboundAnomalyScore => "OUTBOUND_ANOMALY_SCORE",
                    Self::MultipartBoundaryQuoted => "MULTIPART_BOUNDARY_QUOTED",
                    Self::MultipartBoundaryWhitespace => "MULTIPART_BOUNDARY_WHITESPACE",
                    Self::MultipartDataAfter => "MULTIPART_DATA_AFTER",
                    Self::MultipartDataBefore => "MULTIPART_DATA_BEFORE",
                    Self::MultipartFileLimitExceeded => "MULTIPART_FILE_LIMIT_EXCEEDED",
                    Self::MultipartHeaderFolding => "MULTIPART_HEADER_FOLDING",
                    Self::MultipartInvalidHeaderFolding => "MULTIPART_INVALID_HEADER_FOLDING",
                    Self::MultipartInvalidPart => "MULTIPART_INVALID_PART",
                    Self::MultipartLfLine => "MULTIPART_LF_LINE",
                    Self::MultipartMissingSemicolon => "MULTIPART_MISSING_SEMICOLON",
                    Self::MultipartStrictError => "MULTIPART_STRICT_ERROR",
                    Self::MultipartUnmatchedBoundary => "MULTIPART_UNMATCHED_BOUNDARY",
                    Self::WebserverErrorLog => "WEBSERVER_ERROR_LOG",
                }
            }
        }
    };
}

variable_names! {
    "ARGS" => VariableName::Args,
    "ARGS_PATH" => VariableName::ArgsPath,
    "ARGS_GET" => VariableName::ArgsGet,
    "ARGS_POST" => VariableName::ArgsPost,
    "ARGS_NAMES" => VariableName::ArgsNames,
    "ARGS_GET_NAMES" => VariableName::ArgsGetNames,
    "ARGS_POST_NAMES" => VariableName::ArgsPostNames,
    "ARGS_COMBINED_SIZE" => VariableName::ArgsCombinedSize,
    "REQUEST_URI" => VariableName::RequestUri,
    "REQUEST_URI_RAW" => VariableName::RequestUriRaw,
    "REQUEST_FILENAME" => VariableName::RequestFilename,
    "REQUEST_BASENAME" => VariableName::RequestBasename,
    "REQUEST_LINE" => VariableName::RequestLine,
    "REQUEST_METHOD" => VariableName::RequestMethod,
    "REQUEST_PROTOCOL" => VariableName::RequestProtocol,
    "REQUEST_HEADERS" => VariableName::RequestHeaders,
    "REQUEST_HEADERS_NAMES" => VariableName::RequestHeadersNames,
    "REQUEST_COOKIES" => VariableName::RequestCookies,
    "REQUEST_COOKIES_NAMES" => VariableName::RequestCookiesNames,
    "REQUEST_BODY" => VariableName::RequestBody,
    "REQUEST_BODY_LENGTH" => VariableName::RequestBodyLength,
    "ARGUMENTS_LIMIT_REACHED" => VariableName::ArgumentsLimitReached,
    "INBOUND_DATA_ERROR" => VariableName::InboundDataError,
    "OUTBOUND_DATA_ERROR" => VariableName::OutboundDataError,
    "QUERY_STRING" => VariableName::QueryString,
    "RESPONSE_STATUS" => VariableName::ResponseStatus,
    "RESPONSE_PROTOCOL" => VariableName::ResponseProtocol,
    "RESPONSE_HEADERS" => VariableName::ResponseHeaders,
    "RESPONSE_HEADERS_NAMES" => VariableName::ResponseHeadersNames,
    "RESPONSE_ARGS" => VariableName::ResponseArgs,
    "RES_BODY_PROCESSOR" => VariableName::ResBodyProcessor,
    "RES_BODY_ERROR" => VariableName::ResBodyError,
    "RES_BODY_ERROR_MSG" => VariableName::ResBodyErrorMsg,
    "RES_BODY_PROCESSOR_ERROR" => VariableName::ResBodyProcessorError,
    "RES_BODY_PROCESSOR_ERROR_MSG" => VariableName::ResBodyProcessorErrorMsg,
    "RESPONSE_BODY" => VariableName::ResponseBody,
    "RESPONSE_CONTENT_TYPE" => VariableName::ResponseContentType,
    "RESPONSE_CONTENT_LENGTH" => VariableName::ResponseContentLength,
    "REMOTE_ADDR" => VariableName::RemoteAddr,
    "REMOTE_PORT" => VariableName::RemotePort,
    "REMOTE_HOST" => VariableName::RemoteHost,
    "REMOTE_USER" => VariableName::RemoteUser,
    "SERVER_ADDR" => VariableName::ServerAddr,
    "SERVER_PORT" => VariableName::ServerPort,
    "SERVER_NAME" => VariableName::ServerName,
    "TX" => VariableName::Tx,
    "SESSION" => VariableName::Session,
    "ENV" => VariableName::Env,
    "IP" => VariableName::Ip,
    "GLOBAL" => VariableName::Global,
    "RESOURCE" => VariableName::Resource,
    "USER" => VariableName::User,
    "GEO" => VariableName::Geo,
    "MATCHED_VAR" => VariableName::MatchedVar,
    "MATCHED_VARS" => VariableName::MatchedVars,
    "MATCHED_VAR_NAME" => VariableName::MatchedVarName,
    "MATCHED_VARS_NAMES" => VariableName::MatchedVarsNames,
    "TIME" => VariableName::Time,
    "TIME_EPOCH" => VariableName::TimeEpoch,
    "TIME_DAY" => VariableName::TimeDay,
    "TIME_HOUR" => VariableName::TimeHour,
    "TIME_MIN" => VariableName::TimeMin,
    "TIME_SEC" => VariableName::TimeSec,
    "TIME_WDAY" => VariableName::TimeWday,
    "TIME_MON" => VariableName::TimeMon,
    "TIME_YEAR" => VariableName::TimeYear,
    "FILES" => VariableName::Files,
    "FILES_SIZES" => VariableName::FilesSizes,
    "FILES_TMPNAMES" => VariableName::FilesTmpnames,
    "FILES_COMBINED_SIZE" => VariableName::FilesCombinedSize,
    "FILES_NAMES" => VariableName::FilesNames,
    "UNIQUE_ID" => VariableName::UniqueId,
    "DURATION" => VariableName::Duration,
    "HIGHEST_SEVERITY" => VariableName::HighestSeverity,
    "STATUS_LINE" => VariableName::StatusLine,
    "FULL_REQUEST" => VariableName::FullRequest,
    "FULL_REQUEST_LENGTH" => VariableName::FullRequestLength,
    "AUTH_TYPE" => VariableName::AuthType,
    "XML" => VariableName::Xml,
    "REQBODY_PROCESSOR" => VariableName::ReqBodyProcessor,
    "REQBODY_ERROR" => VariableName::ReqBodyError,
    "REQBODY_ERROR_MSG" => VariableName::ReqBodyErrorMsg,
    "REQBODY_PROCESSOR_ERROR" => VariableName::ReqBodyProcessorError,
    "REQBODY_PROCESSOR_ERROR_MSG" => VariableName::ReqBodyProcessorErrorMsg,
    "MULTIPART_STRICT_ERROR" => VariableName::MultipartStrictCheck,
    "MULTIPART_PART_HEADERS" => VariableName::MultipartPartHeaders,
    "MULTIPART_NAME" => VariableName::MultipartName,
    "MULTIPART_FILENAME" => VariableName::MultipartFilename,
    "MULTIPART_FILENAME_CHARSET" => VariableName::MultipartFilenameCharset,
    "MULTIPART_FILENAME_LANGUAGE" => VariableName::MultipartFilenameLanguage,
    "MULTIPART_DUPLICATE_PART_HEADER" => VariableName::MultipartDuplicatePartHeader,
    "MULTIPART_INVALID_QUOTING" => VariableName::MultipartInvalidQuoting,
}

impl VariableName {
    /// Parse a variable name from a string (O(1) lookup).
    // Not `std::str::FromStr`: an unrecognised SecLang token is a plain
    // `None` here, not a parse error with a payload, and callers branch on
    // that. Implementing the trait would force an error type nobody uses.
    #[allow(clippy::should_implement_trait)]
    #[inline]
    pub fn from_str(s: &str) -> Option<Self> {
        // Fast path: check if already uppercase ASCII
        if s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
            return VARIABLE_MAP.get(s).copied();
        }
        // Slow path: need to uppercase
        let mut buf = [0u8; 64];
        let len = s.len().min(64);
        for (i, b) in s.bytes().take(len).enumerate() {
            buf[i] = b.to_ascii_uppercase();
        }
        let upper = std::str::from_utf8(&buf[..len]).ok()?;
        VARIABLE_MAP.get(upper).copied()
    }

    /// Check if this variable is a collection.
    #[inline]
    pub fn is_collection(&self) -> bool {
        matches!(
            self,
            Self::Args
                | Self::ArgsGet
                | Self::ArgsPath
                | Self::ArgsPost
                | Self::ArgsNames
                | Self::RequestHeaders
                | Self::RequestHeadersNames
                | Self::RequestCookies
                | Self::RequestCookiesNames
                | Self::ResponseArgs
                | Self::ResponseHeaders
                | Self::ResponseHeadersNames
                | Self::Tx
                | Self::Session
                | Self::Env
                | Self::Ip
                | Self::Global
                | Self::Resource
                | Self::User
                | Self::Geo
                | Self::MatchedVars
                | Self::MatchedVarsNames
                | Self::Files
                | Self::FilesSizes
                | Self::FilesTmpnames
                | Self::FilesNames
                | Self::MultipartPartHeaders
                | Self::MultipartName
                | Self::MultipartFilename
                | Self::MultipartFilenameCharset
                | Self::MultipartFilenameLanguage
        )
    }
}

/// Parse a variable specification string.
#[inline]
pub fn parse_variables(input: &str) -> Result<Vec<VariableSpec>> {
    let mut variables = Vec::with_capacity(4);
    let mut exclusions: Vec<String> = Vec::new();

    // Split by | for OR conditions
    for part in input.split('|') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Handle exclusions (!VAR)
        if let Some(excluded) = part.strip_prefix('!') {
            exclusions.push(excluded.to_string());
            continue;
        }

        let spec = parse_single_variable(part)?;
        variables.push(spec);
    }

    // Apply exclusions to all variables
    if !exclusions.is_empty() {
        for var in &mut variables {
            var.exclusions = exclusions.clone();
        }
    }

    Ok(variables)
}

/// Parse a `SecRuleUpdateTargetById`-style target list.
///
/// Unlike [`parse_variables`], exclusions (`!TARGET`) are returned separately
/// rather than being attached to the positive specs, because for a target
/// update they must be applied to the *existing* variables of the rule being
/// updated. Returns `(positive_specs, exclusion_strings)`.
pub fn parse_update_targets(input: &str) -> Result<(Vec<VariableSpec>, Vec<String>)> {
    let mut additions = Vec::new();
    let mut exclusions = Vec::new();

    for part in input.split('|') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(excl) = part.strip_prefix('!') {
            // Validate the collection name so a typo'd exclusion is a load
            // error rather than a silently dead exclusion.
            let name_end = excl.find(':').unwrap_or(excl.len());
            let name_str = &excl[..name_end];
            if VariableName::from_str(name_str).is_none() {
                return Err(Error::UnknownVariable {
                    name: name_str.to_string(),
                });
            }
            exclusions.push(excl.to_string());
        } else {
            additions.push(parse_single_variable(part)?);
        }
    }

    Ok((additions, exclusions))
}

/// Parse a single variable specification.
#[inline]
pub(crate) fn parse_single_variable(input: &str) -> Result<VariableSpec> {
    let input = input.trim();
    let bytes = input.as_bytes();

    // Check for count mode (& prefix)
    let (count_mode, input) = if bytes.first() == Some(&b'&') {
        (true, &input[1..])
    } else {
        (false, input)
    };

    // Find colon for selection (use memchr-style search)
    let colon_pos = input.bytes().position(|b| b == b':');

    let (name_str, selection) = match colon_pos {
        Some(pos) => {
            let name = &input[..pos];
            let sel_str = &input[pos + 1..];

            let selection =
                if sel_str.starts_with('/') && sel_str.ends_with('/') && sel_str.len() > 2 {
                    Some(Selection::Regex(sel_str[1..sel_str.len() - 1].to_string()))
                } else {
                    Some(Selection::Key(sel_str.to_string()))
                };

            (name, selection)
        }
        None => (input, None),
    };

    let name = VariableName::from_str(name_str).ok_or_else(|| Error::UnknownVariable {
        name: name_str.to_string(),
    })?;

    Ok(VariableSpec {
        name,
        selection,
        count_mode,
        exclusions: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_variable() {
        let vars = parse_variables("REQUEST_URI").unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, VariableName::RequestUri);
        assert!(vars[0].selection.is_none());
        assert!(!vars[0].count_mode);
    }

    #[test]
    fn test_parse_variable_with_selection() {
        let vars = parse_variables("ARGS:username").unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, VariableName::Args);
        assert!(matches!(&vars[0].selection, Some(Selection::Key(k)) if k == "username"));
    }

    #[test]
    fn test_parse_variable_with_regex() {
        let vars = parse_variables("ARGS:/^user/").unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, VariableName::Args);
        assert!(matches!(&vars[0].selection, Some(Selection::Regex(r)) if r == "^user"));
    }

    #[test]
    fn test_parse_multipart_part_headers() {
        // Used by CRS REQUEST-922; must parse rather than erroring as unknown.
        let vars = parse_variables("MULTIPART_PART_HEADERS").unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, VariableName::MultipartPartHeaders);
    }

    #[test]
    fn test_parse_count_mode() {
        let vars = parse_variables("&ARGS").unwrap();
        assert_eq!(vars.len(), 1);
        assert!(vars[0].count_mode);
    }

    #[test]
    fn test_parse_multiple_variables() {
        let vars = parse_variables("REQUEST_URI|ARGS|REQUEST_HEADERS").unwrap();
        assert_eq!(vars.len(), 3);
    }

    #[test]
    fn test_variable_lookup_case_insensitive() {
        assert_eq!(
            VariableName::from_str("REQUEST_URI"),
            Some(VariableName::RequestUri)
        );
        assert_eq!(
            VariableName::from_str("request_uri"),
            Some(VariableName::RequestUri)
        );
        assert_eq!(
            VariableName::from_str("Request_Uri"),
            Some(VariableName::RequestUri)
        );
    }
}
