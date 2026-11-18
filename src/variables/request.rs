//! Request data for variable resolution.

use super::collection::{Collection, HashMapCollection};
use super::ByteValue;

/// Request data container.
#[derive(Debug, Clone)]
pub struct RequestData {
    argument_limit: usize,
    request_json_depth_limit: usize,
    /// A query or body processor dropped entries at its configured argument limit.
    pub arguments_limit_reached: bool,
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

impl Default for RequestData {
    fn default() -> Self {
        Self {
            argument_limit: super::DEFAULT_ARGUMENT_LIMIT,
            request_json_depth_limit: super::json::DEFAULT_DEPTH_LIMIT,
            arguments_limit_reached: false,
            method: Default::default(),
            uri: Default::default(),
            uri_raw: Default::default(),
            path: Default::default(),
            query_string: Default::default(),
            protocol: Default::default(),
            binary_uri: Default::default(),
            binary_path: Default::default(),
            binary_query: Default::default(),
            binary_method: Default::default(),
            binary_protocol: Default::default(),
            headers: HashMapCollection::named(),
            args_get: HashMapCollection::named(),
            args_post: HashMapCollection::named(),
            cookies: HashMapCollection::named(),
            xml: HashMapCollection::named(),
            multipart_part_headers: HashMapCollection::named(),
            files: HashMapCollection::named(),
            files_names: HashMapCollection::named(),
            files_sizes: HashMapCollection::named(),
            files_combined_size: Default::default(),
            multipart_names: HashMapCollection::named(),
            multipart_filenames: HashMapCollection::named(),
            multipart_filename_charsets: HashMapCollection::named(),
            multipart_filename_languages: HashMapCollection::named(),
            multipart_strict_error: Default::default(),
            multipart_duplicate_part_header: Default::default(),
            multipart_invalid_quoting: Default::default(),
            body_processor: Default::default(),
            body_error: Default::default(),
            body: Default::default(),
            inbound_data_error: Default::default(),
            client_ip: Default::default(),
            client_port: Default::default(),
            server_name: Default::default(),
            server_addr: Default::default(),
            server_port: Default::default(),
        }
    }
}

impl RequestData {
    /// Create new request data.
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_limits(argument_limit: usize, request_json_depth_limit: usize) -> Self {
        Self {
            argument_limit,
            request_json_depth_limit,
            ..Self::default()
        }
    }

    pub(crate) fn argument_limit_flag(&self) -> &'static [u8] {
        if self.arguments_limit_reached {
            b"1"
        } else {
            b"0"
        }
    }

    /// Set the URI and parse path/query string.
    pub fn set_uri(&mut self, uri: &str) {
        self.set_uri_bytes(uri.as_bytes());
    }

    /// Set a request target without replacing invalid UTF-8 or decoded bytes.
    pub fn set_uri_bytes(&mut self, uri: &[u8]) {
        let (display, binary) = component_strings(uri);
        self.uri_raw = display.clone();
        self.uri = display;
        self.binary_uri = binary;

        let end = memchr::memchr2(b'?', b'#', uri).unwrap_or(uri.len());
        let raw_path = &uri[..end];
        let query = if uri.get(end) == Some(&b'?') {
            let tail = &uri[end + 1..];
            &tail[..memchr::memchr(b'#', tail).unwrap_or(tail.len())]
        } else {
            &[]
        };
        (self.query_string, self.binary_query) = component_strings(query);
        self.args_get.clear();
        self.arguments_limit_reached |=
            parse_form_bytes(query, &mut self.args_get, self.argument_limit);

        match String::from_utf8(decoded_request_path_bytes(raw_path)) {
            Ok(path) => {
                self.path = path;
                self.binary_path = None;
            }
            Err(error) => {
                self.binary_path = Some(ByteValue::from(error.into_bytes()));
                // The public text field historically exposes the undecoded path
                // when percent decoding produces non-UTF-8.
                self.path = component_strings(raw_path).0;
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
        (self.method, self.binary_method) = component_strings(value);
    }
    /// Set protocol bytes; textual presentation is never used for matching.
    pub fn set_protocol_bytes(&mut self, value: &[u8]) {
        (self.protocol, self.binary_protocol) = component_strings(value);
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
        // The first Content-Type selects form processors before phase 1,
        // including empty bodies. Later duplicate headers must not change it.
        if lower == b"content-type" && self.headers.first_value_bytes(b"content-type").is_none() {
            let media = trim_header_leading_space(value);
            if media.get(..33).is_some_and(|prefix| {
                prefix.eq_ignore_ascii_case(b"application/x-www-form-urlencoded")
            }) {
                self.body_processor = "URLENCODED".into();
            } else if media
                .get(..19)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"multipart/form-data"))
            {
                self.body_processor = "MULTIPART".into();
            }
        }
        self.headers.add_named_bytes(lower, name, value);
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
        self.arguments_limit_reached |=
            parse_form_bytes(&self.body, &mut self.args_post, self.argument_limit);
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

        let result = super::json::parse(
            &self.body,
            &mut self.args_post,
            self.argument_limit,
            self.request_json_depth_limit,
            &mut self.arguments_limit_reached,
        );
        self.body_error = result.as_ref().err().cloned();
        result
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

fn component_strings(bytes: &[u8]) -> (String, Option<ByteValue>) {
    match std::str::from_utf8(bytes) {
        Ok(value) => (value.to_owned(), None),
        Err(_) => {
            let value = ByteValue::from(bytes);
            (value.to_string(), Some(value))
        }
    }
}

/// Decode the path after query and fragment splitting. Plus is literal here.
fn decoded_request_path_bytes(input: &[u8]) -> Vec<u8> {
    let mut path = input;
    if input.first().is_some_and(u8::is_ascii_alphabetic) {
        if let Some(colon) = memchr::memchr(b':', input) {
            if let Some(authority) = input[colon + 1..].strip_prefix(b"//") {
                if input[..colon]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(b))
                {
                    path = &authority[memchr::memchr(b'/', authority).unwrap_or(authority.len())..];
                }
            }
        }
    }

    let mut escapes = memchr::memchr_iter(b'%', path);
    let Some(first) = escapes.next() else {
        return path.to_vec();
    };
    let mut decoded = Vec::with_capacity(path.len());
    let mut start = 0;
    for pos in std::iter::once(first).chain(escapes) {
        let Some(hex) = path.get(pos + 1..pos + 3).and_then(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        }) else {
            // A malformed escape preserves the complete original target path,
            // including the authority of an absolute URI.
            return input.to_vec();
        };
        decoded.extend_from_slice(&path[start..pos]);
        decoded.push(hex);
        start = pos + 3;
    }
    decoded.extend_from_slice(&path[start..]);
    decoded
}

// Go strings.TrimSpace recognizes Unicode whitespace even when later header
// bytes are opaque. Decode only the leading code point, never replace bytes.
fn trim_header_leading_space(mut value: &[u8]) -> &[u8] {
    while let Some(&first) = value.first() {
        let width = match first {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => break,
        };
        let Some(character) = value
            .get(..width)
            .and_then(|prefix| std::str::from_utf8(prefix).ok())
            .and_then(|text| text.chars().next())
        else {
            break;
        };
        if !character.is_whitespace() {
            break;
        }
        value = &value[width..];
    }
    value
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

fn parse_form_bytes(
    mut input: &[u8],
    collection: &mut HashMapCollection,
    mut remaining: usize,
) -> bool {
    // Keep an escaped or opaque field from forcing unrelated plain fields
    // through the byte decoder. Always cut at an actual form separator.
    const BLOCK_BYTES: usize = 1024;
    while let Some(tail) = input.get(BLOCK_BYTES..) {
        let Some(separator) = memchr::memchr(b'&', tail) else {
            break;
        };
        let end = BLOCK_BYTES + separator;
        if parse_form_block(&input[..end], collection, &mut remaining) {
            return true;
        }
        input = &input[end + 1..];
    }
    parse_form_block(input, collection, &mut remaining)
}

fn parse_form_block(
    input: &[u8],
    collection: &mut HashMapCollection,
    remaining: &mut usize,
) -> bool {
    // Unescaped text needs no per-field decoder or UTF-8 validation.
    if memchr::memchr2(b'%', b'+', input).is_none() {
        if let Ok(text) = std::str::from_utf8(input) {
            for pair in text.split('&').filter(|pair| !pair.is_empty()) {
                if *remaining == 0 {
                    return true;
                }
                *remaining -= 1;
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                collection.add_bytes(key, value);
            }
            return false;
        }
    }
    for pair in input.split(|&b| b == b'&').filter(|pair| !pair.is_empty()) {
        if *remaining == 0 {
            return true;
        }
        *remaining -= 1;
        let equal = pair.iter().position(|&b| b == b'=');
        let (key, value) = equal.map_or((pair, &b""[..]), |i| (&pair[..i], &pair[i + 1..]));
        collection.add_bytes(
            crate::transformations::bytes::url_decode_stage(key, false),
            crate::transformations::bytes::url_decode_stage(value, false),
        );
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_parsing_preserves_observed_names_binary_data_and_field_boundaries() {
        use crate::variables::ByteCollection;

        fn check(input: &[u8], expected: &[(&[u8], &[u8], &[u8])]) {
            let mut request = RequestData::new();
            let mut uri = b"/form?".to_vec();
            uri.extend_from_slice(input);
            request.set_uri_bytes(&uri);
            request.body.extend_from_slice(input);
            request.parse_form_body();
            assert_eq!(request.args_get.all_bytes_with_names(), expected);
            assert_eq!(request.args_post.all_bytes_with_names(), expected);
        }

        // The first '=' separates a field. Empty segments vanish, while an
        // empty name and a bare name remain separate observed members.
        let plain: &[(&[u8], &[u8], &[u8])] = &[
            (b"k", b"K", b"one"),
            (b"k", b"k", b"two=2"),
            (b"", b"", b"empty"),
            (b"bare", b"bare", b""),
        ];
        check(b"&&K=one&=empty&k=two=2&bare&&", plain);
        check(b"%4B=one&=empty&k=two%3D2&bare&", plain);
        check(b"K=one&=empty&k=two=2&b%61re", plain);
        check(
            "Ö=é&ö=茶".as_bytes(),
            &[
                ("ö".as_bytes(), "Ö".as_bytes(), "é".as_bytes()),
                ("ö".as_bytes(), "ö".as_bytes(), "茶".as_bytes()),
            ],
        );
        check(
            b"k=%ff&x=a%26b&bad=%G1%&plus=a+b&plus=a%2Bb",
            &[
                (b"k", b"k", b"\xff"),
                (b"x", b"x", b"a&b"),
                (b"bad", b"bad", b"%G1%"),
                (b"plus", b"plus", b"a b"),
                (b"plus", b"plus", b"a+b"),
            ],
        );
        check(
            b"x=\xff&\xfe=%2b",
            &[(b"x", b"x", b"\xff"), (b"\xfe", b"\xfe", b"+")],
        );
    }

    #[test]
    fn form_decoding_preserves_fields_across_block_boundaries() {
        use crate::variables::ByteCollection;

        for separator in [1023, 1024, 1025, 8192] {
            for opaque in [false, true] {
                let byte = if opaque { 0xff } else { b'a' };
                let first = vec![byte; separator - 2];
                let second = vec![if opaque { b'z' } else { 0xfe }; 2048];
                let mut form = b"A=".to_vec();
                form.extend_from_slice(&first);
                form.extend_from_slice(b"&&B=");
                form.extend_from_slice(&second);
                form.extend_from_slice(b"&a=%26%3D&b=two+words&bare");

                let mut req = RequestData::new();
                parse_form_bytes(&form, &mut req.args_post, usize::MAX);
                let expected: &[(&[u8], &[u8], &[u8])] = &[
                    (b"a", b"A", &first),
                    (b"a", b"a", b"&="),
                    (b"b", b"B", &second),
                    (b"b", b"b", b"two words"),
                    (b"bare", b"bare", b""),
                ];
                assert_eq!(req.args_post.all_bytes_with_names(), expected);

                // The threshold may also lie within a sole field.
                let mut req = RequestData::new();
                parse_form_bytes(&form[..separator], &mut req.args_get, usize::MAX);
                assert_eq!(req.args_get.all_bytes_with_names(), &expected[..1]);
            }
        }
    }

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
