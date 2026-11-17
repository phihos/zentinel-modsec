//! Request data for variable resolution.

use super::collection::{Collection, HashMapCollection};
use super::json::JsonNode;
use super::ByteValue;

/// Request data container.
#[derive(Debug, Clone, Default)]
pub struct RequestData {
    /// HTTP method.
    pub method: String,
    /// Request URI (with query string).
    pub uri: String,
    /// Raw URI.
    pub uri_raw: String,
    /// Request path (without query string).
    pub path: String,
    /// Query string.
    pub query_string: String,
    /// HTTP protocol version.
    pub protocol: String,
    /// Original URI bytes when the legacy text field cannot represent them.
    pub(crate) binary_uri: Option<ByteValue>,
    /// Decoded path bytes when percent decoding produces non-UTF-8 data.
    pub(crate) binary_path: Option<ByteValue>,
    /// Original query bytes when the legacy text field cannot represent them.
    pub(crate) binary_query: Option<ByteValue>,
    /// Original method bytes when not UTF-8.
    pub(crate) binary_method: Option<ByteValue>,
    /// Original protocol bytes when not UTF-8.
    pub(crate) binary_protocol: Option<ByteValue>,
    /// Request headers.
    pub headers: HashMapCollection,
    /// GET arguments.
    pub args_get: HashMapCollection,
    /// POST arguments.
    pub args_post: HashMapCollection,
    /// Cookies.
    pub cookies: HashMapCollection,
    /// XML attribute and text values keyed by Coraza's two supported selectors
    /// (`//@*` and `/*`). XML markup never becomes HTTP argument names.
    pub xml: HashMapCollection,
    /// Multipart part headers (key = part name, value = full header line),
    /// populated by the multipart body processor. Mirrors ModSecurity's
    /// `MULTIPART_PART_HEADERS` collection.
    pub multipart_part_headers: HashMapCollection,
    /// Uploaded files (key = part name, value = client-supplied filename),
    /// populated by the multipart body processor. Backs `FILES`/`FILES_NAMES`.
    pub files: HashMapCollection,
    /// Uploaded field names (one value per file part).
    pub files_names: HashMapCollection,
    /// Uploaded payload byte sizes, keyed by the original filename bytes.
    pub files_sizes: HashMapCollection,
    /// Sum of multipart field and file payload bytes, excluding framing.
    pub files_combined_size: usize,
    /// Multipart field names and all filename interpretations.
    pub multipart_names: HashMapCollection,
    /// Filenames keyed by multipart part name.
    pub multipart_filenames: HashMapCollection,
    /// Extended filename charsets, without transcoding the filename bytes.
    pub multipart_filename_charsets: HashMapCollection,
    /// Extended filename language parameters.
    pub multipart_filename_languages: HashMapCollection,
    /// Multipart syntax or parser-disagreement flags.
    pub multipart_strict_error: bool,
    /// A duplicate multipart header or conflicting parameter was present.
    pub multipart_duplicate_part_header: bool,
    /// An extended filename used invalid quoted-string syntax.
    pub multipart_invalid_quoting: bool,
    /// Name of the body processor that handled the request body
    /// (`MULTIPART`, `URLENCODED`, `JSON`, or empty when none ran). Backs
    /// `REQBODY_PROCESSOR`.
    pub body_processor: String,
    /// Why the body processor could not process the body, if it failed.
    ///
    /// Backs `REQBODY_ERROR` (1 when set, 0 otherwise) and
    /// `REQBODY_ERROR_MSG`. CRS rule 200002 blocks on this, which only works
    /// if a failed parse is observable: a strict parser rejecting a payload
    /// that the origin application happily accepts is a bypass when it
    /// happens quietly.
    pub body_error: Option<String>,
    /// Request body.
    pub body: Vec<u8>,
    /// Acquisition reached its body limit; a partial body may end mid-part.
    pub inbound_data_error: bool,
    /// Client IP address.
    pub client_ip: String,
    /// Client port.
    pub client_port: u16,
    /// Server name.
    pub server_name: String,
    /// Local address the connection was accepted on. Backs `SERVER_ADDR`.
    pub server_addr: String,
    /// Server port.
    pub server_port: u16,
}

impl RequestData {
    /// Create new request data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the URI and parse path/query string.
    pub fn set_uri(&mut self, uri: &str) {
        self.binary_uri = None;
        self.binary_query = None;
        self.binary_path = None;
        self.uri = uri.to_string();
        self.uri_raw = uri.to_string();

        if let Some(pos) = uri.find('?') {
            self.path = decoded_request_path(&uri[..pos]);
            self.query_string = uri[pos + 1..].to_string();
            self.parse_query_string(&self.query_string.clone());
        } else {
            self.path = decoded_request_path(uri);
            self.query_string.clear();
        }
    }

    /// Set a request target without replacing invalid UTF-8 or decoded bytes.
    pub fn set_uri_bytes(&mut self, uri: &[u8]) {
        match std::str::from_utf8(uri) {
            Ok(text) => self.set_uri(text),
            Err(_) => self.set_uri(ByteValue::from(uri).display_text()),
        }
        let path_end = uri.iter().position(|&b| b == b'?').unwrap_or(uri.len());
        let raw_path = &uri[..path_end];
        if raw_path.contains(&b'%') || std::str::from_utf8(raw_path).is_err() {
            let decoded = decoded_request_path_bytes(raw_path);
            if std::str::from_utf8(&decoded).is_err() {
                self.binary_path = Some(ByteValue::from(decoded));
            }
        }
        if std::str::from_utf8(uri).is_err() {
            self.binary_uri = Some(ByteValue::from(uri));
            self.args_get.clear();
            if path_end < uri.len() {
                let query = &uri[path_end + 1..];
                self.binary_query = Some(ByteValue::from(query));
                parse_form_bytes(query, &mut self.args_get);
            }
        }
    }

    /// Original request target bytes.
    pub fn uri_bytes(&self) -> &[u8] {
        self.binary_uri
            .as_ref()
            .map_or(self.uri_raw.as_bytes(), ByteValue::as_bytes)
    }
    /// Decoded path bytes, including invalid UTF-8 created by percent decoding.
    pub fn path_bytes(&self) -> &[u8] {
        self.binary_path
            .as_ref()
            .map_or(self.path.as_bytes(), ByteValue::as_bytes)
    }
    /// Original query string bytes.
    pub fn query_bytes(&self) -> &[u8] {
        self.binary_query
            .as_ref()
            .map_or(self.query_string.as_bytes(), ByteValue::as_bytes)
    }
    /// Original HTTP method bytes.
    pub fn method_bytes(&self) -> &[u8] {
        self.binary_method
            .as_ref()
            .map_or(self.method.as_bytes(), ByteValue::as_bytes)
    }
    /// Original HTTP protocol bytes.
    pub fn protocol_bytes(&self) -> &[u8] {
        self.binary_protocol
            .as_ref()
            .map_or(self.protocol.as_bytes(), ByteValue::as_bytes)
    }
    /// Set method bytes; textual presentation is never used for matching.
    pub fn set_method_bytes(&mut self, value: &[u8]) {
        let value = ByteValue::from(value);
        self.method = value.to_string();
        self.binary_method = value.as_utf8().is_err().then_some(value);
    }
    /// Set protocol bytes; textual presentation is never used for matching.
    pub fn set_protocol_bytes(&mut self, value: &[u8]) {
        let value = ByteValue::from(value);
        self.protocol = value.to_string();
        self.binary_protocol = value.as_utf8().is_err().then_some(value);
    }

    /// Set the HTTP method.
    pub fn set_method(&mut self, method: &str) {
        self.binary_method = None;
        self.method = method.to_string();
    }

    /// Set the protocol.
    pub fn set_protocol(&mut self, protocol: &str) {
        self.binary_protocol = None;
        self.protocol = protocol.to_string();
    }

    /// Add a request header.
    pub fn add_header(&mut self, name: &str, value: &str) {
        self.add_header_bytes(name.as_bytes(), value.as_bytes());
    }

    /// Add original header name/value bytes without UTF-8 replacement.
    pub fn add_header_bytes(&mut self, name: &[u8], value: &[u8]) {
        let lower = name.to_ascii_lowercase();
        if lower == b"cookie" {
            self.parse_cookie_header_bytes(value);
        }
        self.headers.add_bytes(lower, value);
    }

    fn parse_cookie_header_bytes(&mut self, value: &[u8]) {
        for pair in value.split(|&b| b == b';') {
            let pair = trim_ascii(pair);
            if pair.is_empty() {
                continue;
            }
            let equal = pair.iter().position(|&b| b == b'=');
            match equal {
                Some(i) => self
                    .cookies
                    .add_bytes(trim_ascii(&pair[..i]), trim_ascii(&pair[i + 1..])),
                None => self.cookies.add_bytes(pair, &b""[..]),
            }
        }
    }

    /// Append to request body.
    pub fn append_body(&mut self, data: &[u8]) {
        self.body.extend_from_slice(data);
    }

    /// Get body as string.
    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// REQUEST_BODY's original bytes, observing processor-specific visibility.
    pub fn request_body_bytes_variable(&self) -> &[u8] {
        if matches!(self.body_processor.as_str(), "URLENCODED" | "RAW") {
            &self.body
        } else {
            b""
        }
    }

    /// Public REQUEST_BODY value, distinct from the internally retained bytes.
    /// Coraza populates it only for the URLENCODED and RAW processors.
    pub fn request_body_variable(&self) -> String {
        if matches!(self.body_processor.as_str(), "URLENCODED" | "RAW") {
            self.body_str()
        } else {
            String::new()
        }
    }

    /// Structured processors leave REQUEST_BODY_LENGTH at its initial zero.
    pub fn request_body_length_variable(&self) -> String {
        if matches!(self.body_processor.as_str(), "URLENCODED" | "RAW") {
            self.body_length().to_string()
        } else {
            "0".into()
        }
    }

    /// Get body length.
    pub fn body_length(&self) -> usize {
        self.body.len()
    }

    /// Parse query string into args_get.
    fn parse_query_string(&mut self, qs: &str) {
        parse_form_bytes(qs.as_bytes(), &mut self.args_get);
    }

    /// Parse multipart without decoding binary fields or filenames as UTF-8.
    pub fn parse_multipart_body(&mut self, content_type: &str) -> bool {
        self.parse_multipart_body_bytes(content_type.as_bytes())
    }

    /// Byte-preserving multipart Content-Type and body processing.
    /// Returns false when the Content-Type carries no usable boundary; parser
    /// failures remain visible through body and strict-error variables.
    pub fn parse_multipart_body_bytes(&mut self, content_type: &[u8]) -> bool {
        self.body_processor = "MULTIPART".into();
        let parsed = super::multipart::parse(&self.body, content_type, self.inbound_data_error);
        self.args_post = parsed.fields;
        self.files = parsed.files;
        self.files_names = parsed.file_names;
        self.files_sizes = parsed.file_sizes;
        self.files_combined_size = parsed.combined_size;
        self.multipart_part_headers = parsed.headers;
        self.multipart_names = parsed.names;
        self.multipart_filenames = parsed.filenames;
        self.multipart_filename_charsets = parsed.charsets;
        self.multipart_filename_languages = parsed.languages;
        self.multipart_strict_error = parsed.strict;
        self.multipart_duplicate_part_header = parsed.duplicate;
        self.multipart_invalid_quoting = parsed.invalid_quoting;
        self.body_error = parsed.error;
        parsed.has_boundary
    }

    /// Parse form body into args_post.
    pub fn parse_form_body(&mut self) {
        parse_form_bytes(&self.body, &mut self.args_post);
    }

    /// Parse a JSON body into `args_post`, mirroring ModSecurity's JSON
    /// request body processor.
    ///
    /// Every scalar in the document becomes one argument named by its path,
    /// prefixed with `json.` and joined with `.`, with array indices as path
    /// segments — the naming libmodsecurity uses, so CRS exclusions written as
    /// `ARGS:json.user.name` keep working:
    ///
    /// ```text
    /// {"user": {"name": "bob"}, "tags": ["a", "b"]}
    ///   -> json.user.name = bob
    ///      json.tags.0    = a
    ///      json.tags.1    = b
    /// ```
    ///
    /// Returns `Ok(())` on success, or the reason the body could not be
    /// processed. The caller must surface that reason rather than treating it
    /// as an empty body: a strict parser rejecting a payload that the origin
    /// application accepts is a bypass if it happens quietly.
    pub fn parse_json_body(&mut self) -> Result<(), String> {
        self.body_processor = "JSON".to_string();

        // A body that is empty or only whitespace has nothing to inspect, and
        // is not a parse failure. Clients legitimately send an empty body with
        // `Content-Type: application/json` on POST and DELETE; reporting that
        // as an error would make CRS rule 200002 block them.
        if self.body.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(());
        }

        let value: JsonNode = match serde_json::from_slice(&self.body) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("JSON parsing error: {e}");
                self.body_error = Some(msg.clone());
                return Err(msg);
            }
        };

        let mut count = 0usize;
        let mut path = String::from("json");
        let truncated = flatten_json(&value, &mut path, &mut self.args_post, &mut count, 0);

        if truncated {
            let msg = format!(
                "JSON body exceeded processing limits ({MAX_JSON_ARGS} arguments or \
                 {MAX_JSON_DEPTH} levels of nesting); only part of the body was inspected"
            );
            self.body_error = Some(msg.clone());
            return Err(msg);
        }

        Ok(())
    }

    /// Parse XML values into their own collection, without inventing HTTP
    /// arguments. `XML:/*` selects text and `XML://@*` attribute values.
    pub fn parse_xml_body(&mut self) -> Result<(), String> {
        self.body_processor = "XML".to_string();
        self.xml.clear();
        self.body_error = None;
        let result = super::xml::parse(&self.body);
        let error = match result {
            Ok((values, suppressed_entity)) => {
                self.xml = values;
                suppressed_entity.map(|name| {
                    format!(
                        "XML body references the undeclared or custom entity '&{name};', which \
                     is not expanded; any content it carries was not inspected"
                    )
                })
            }
            Err(error) => Some(error),
        };
        if let Some(error) = error {
            self.body_error = Some(error.clone());
            return Err(error);
        }
        Ok(())
    }

    /// Get all arguments (GET + POST combined).
    pub fn all_args(&self) -> Vec<(&str, &str)> {
        let mut all = self.args_get.all();
        all.extend(self.args_post.all());
        all
    }
}

/// Decode only the path component. Query delimiters are split by the caller
/// before decoding, and a literal plus in a path is never form-decoded.
fn decoded_request_path(input: &str) -> String {
    String::from_utf8(decoded_request_path_bytes(input.as_bytes()))
        .unwrap_or_else(|_| input.to_string())
}

fn decoded_request_path_bytes(input: &[u8]) -> Vec<u8> {
    let without_fragment = input.split(|&b| b == b'#').next().unwrap_or(input);
    let path = if let Some(scheme_end) = without_fragment.windows(3).position(|part| part == b"://")
    {
        let scheme = &without_fragment[..scheme_end];
        let rest = &without_fragment[scheme_end + 3..];
        if !scheme.is_empty()
            && scheme.iter().enumerate().all(|(i, b)| {
                b.is_ascii_alphabetic() || i > 0 && (b.is_ascii_digit() || b"+-.".contains(b))
            })
        {
            rest.iter()
                .position(|&b| b == b'/')
                .map_or(&b""[..], |offset| &rest[offset..])
        } else {
            without_fragment
        }
    } else {
        without_fragment
    };
    for (i, &byte) in path.iter().enumerate() {
        if byte == b'%'
            && !path
                .get(i + 1..i + 3)
                .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
        {
            return input.to_vec();
        }
    }
    percent_encoding::percent_decode(path).collect()
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn parse_form_bytes(input: &[u8], collection: &mut HashMapCollection) {
    for pair in input.split(|&b| b == b'&').filter(|pair| !pair.is_empty()) {
        let equal = pair.iter().position(|&b| b == b'=');
        let (key, value) = equal.map_or((pair, &b""[..]), |i| (&pair[..i], &pair[i + 1..]));
        collection.add_bytes(
            crate::transformations::bytes::url_decode(key, false, true),
            crate::transformations::bytes::url_decode(value, false, true),
        );
    }
}

/// Most arguments extracted from a single JSON body.
///
/// A hostile body can be small on the wire and still expand into an enormous
/// number of arguments — `[[[...]]]` or a long array of scalars — each of
/// which would then be run through every rule's operator. The cap bounds that
/// work; exceeding it is reported as a body-processor error rather than
/// silently truncating, since a partially inspected body is not a safe body.
const MAX_JSON_ARGS: usize = 4096;

/// Deepest JSON nesting the flattener will descend.
///
/// `serde_json` already refuses to *parse* beyond its own recursion limit;
/// this bounds the separate recursion done here.
const MAX_JSON_DEPTH: usize = 64;

/// Flatten a JSON value into `args`, naming each scalar by its path.
///
/// `path` is the prefix built so far and is restored before returning, so one
/// buffer is reused for the whole document. Returns `true` if a limit was hit
/// and the result is therefore incomplete.
fn flatten_json(
    value: &JsonNode,
    path: &mut String,
    args: &mut HashMapCollection,
    count: &mut usize,
    depth: usize,
) -> bool {
    if depth > MAX_JSON_DEPTH {
        return true;
    }

    match value {
        JsonNode::Object(entries) => {
            // Duplicate keys produce repeated entries under the same argument
            // name, so every value a client sent is inspected. Keeping only
            // one would let a parser differential hide a payload.
            for (key, child) in entries {
                let restore = path.len();
                path.push('.');
                path.push_str(key);
                let truncated = flatten_json(child, path, args, count, depth + 1);
                path.truncate(restore);
                if truncated {
                    return true;
                }
            }
            false
        }
        JsonNode::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let restore = path.len();
                path.push('.');
                path.push_str(&index.to_string());
                let truncated = flatten_json(child, path, args, count, depth + 1);
                path.truncate(restore);
                if truncated {
                    return true;
                }
            }
            false
        }
        // Scalars are the leaves that become arguments. `null` contributes an
        // empty value rather than being skipped, so a rule testing for the
        // presence of a key still sees it.
        JsonNode::String(s) => push_json_arg(path, s.clone(), args, count),
        JsonNode::Number(n) => push_json_arg(path, n.clone(), args, count),
        JsonNode::Bool(b) => push_json_arg(path, b.to_string(), args, count),
        JsonNode::Null => push_json_arg(path, String::new(), args, count),
    }
}

/// Record one flattened scalar. Returns `true` once the argument cap is hit.
fn push_json_arg(
    path: &str,
    value: String,
    args: &mut HashMapCollection,
    count: &mut usize,
) -> bool {
    if *count >= MAX_JSON_ARGS {
        return true;
    }
    *count += 1;
    args.add(path.to_string(), value);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookie_header() {
        let mut req = RequestData::new();
        req.add_header("Cookie", "session=abc123; theme=dark; bare");
        assert_eq!(req.cookies.get("session"), Some(vec!["abc123"]));
        assert_eq!(req.cookies.get("theme"), Some(vec!["dark"]));
        assert_eq!(req.cookies.get("bare"), Some(vec![""]));
    }

    #[test]
    fn test_parse_multipart_body_fields_and_headers() {
        let mut req = RequestData::new();
        let body = "--XyZ\r\n\
                    Content-Disposition: form-data; name=\"field1\"\r\n\
                    \r\n\
                    value1\r\n\
                    --XyZ\r\n\
                    Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    file contents\r\n\
                    --XyZ--\r\n";
        req.append_body(body.as_bytes());
        assert!(req.parse_multipart_body("multipart/form-data; boundary=XyZ"));

        // Form field lands in ARGS_POST.
        assert_eq!(req.args_post.get("field1"), Some(vec!["value1"]));
        // File part does NOT land in ARGS_POST but in FILES.
        assert_eq!(req.args_post.get("upload"), None);
        assert_eq!(req.files.get(""), Some(vec!["a.txt"]));
        assert_eq!(req.files_names.get(""), Some(vec!["upload"]));

        // Every part header line is recorded under the part name.
        let field1_headers = req.multipart_part_headers.get("field1").unwrap();
        assert_eq!(
            field1_headers,
            vec!["Content-Disposition: form-data; name=\"field1\""]
        );
        let upload_headers = req.multipart_part_headers.get("upload").unwrap();
        assert!(upload_headers.contains(&"Content-Type: text/plain"));
        assert_eq!(req.body_processor, "MULTIPART");
    }

    #[test]
    fn test_parse_multipart_body_quoted_boundary_and_lf_only() {
        let mut req = RequestData::new();
        let body = "--b1\nContent-Disposition: form-data; name=\"k\"\n\nv\n--b1--\n";
        req.append_body(body.as_bytes());
        assert!(req.parse_multipart_body("multipart/form-data; boundary=\"b1\""));
        assert_eq!(req.args_post.get("k"), Some(vec!["v"]));
    }

    #[test]
    fn test_parse_multipart_body_missing_boundary() {
        let mut req = RequestData::new();
        req.append_body(b"irrelevant");
        assert!(!req.parse_multipart_body("multipart/form-data"));
        assert_eq!(req.body_processor, "MULTIPART");
        assert!(req.body_error.is_some());
        assert!(req.multipart_strict_error);
    }
}
