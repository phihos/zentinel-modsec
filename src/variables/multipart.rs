//! Byte-oriented multipart values and strict parsing diagnostics.
use super::collection::HashMapCollection;
use std::collections::{HashMap, HashSet};

/// Named files remain available through logging and are unlinked on the last
/// request-data drop. Close each file after writing to bound descriptor usage.
#[derive(Debug, Default)]
pub(crate) struct UploadedFiles {
    pub names: HashMapCollection,
    paths: Vec<tempfile::TempPath>,
}

impl UploadedFiles {
    fn store(&mut self, bytes: &[u8], directory: Option<&std::path::Path>) -> std::io::Result<()> {
        use std::io::Write;
        let mut file = tempfile::Builder::new()
            .prefix("crzmp")
            .tempfile_in(directory.map_or_else(std::env::temp_dir, std::path::Path::to_path_buf))?;
        file.write_all(bytes)?;
        let path = file.into_temp_path();
        self.names
            .add_bytes(b"".as_slice(), path.as_os_str().as_encoded_bytes());
        self.paths.push(path);
        Ok(())
    }
}

pub(super) struct Multipart {
    pub uploads: Option<UploadedFiles>,
    pub fields: HashMapCollection,
    pub files: HashMapCollection,
    pub file_names: HashMapCollection,
    pub file_sizes: HashMapCollection,
    pub headers: HashMapCollection,
    pub names: HashMapCollection,
    pub filenames: HashMapCollection,
    pub charsets: HashMapCollection,
    pub languages: HashMapCollection,
    pub combined_size: usize,
    pub strict: bool,
    pub duplicate: bool,
    pub invalid_quoting: bool,
    pub error: Option<String>,
    pub has_boundary: bool,
}

impl Default for Multipart {
    fn default() -> Self {
        Self {
            uploads: None,
            fields: HashMapCollection::named(),
            files: HashMapCollection::named(),
            file_names: HashMapCollection::named(),
            file_sizes: HashMapCollection::named(),
            headers: HashMapCollection::named(),
            names: HashMapCollection::named(),
            filenames: HashMapCollection::named(),
            charsets: HashMapCollection::named(),
            languages: HashMapCollection::named(),
            combined_size: Default::default(),
            strict: Default::default(),
            duplicate: Default::default(),
            invalid_quoting: Default::default(),
            error: Default::default(),
            has_boundary: Default::default(),
        }
    }
}

#[derive(Clone)]
struct Parameter {
    key: Vec<u8>,
    value: Vec<u8>,
    quoted: bool,
    raw_quoted: Option<Vec<u8>>,
}
#[derive(Default)]
struct Parameters {
    media: Vec<u8>,
    values: Vec<Parameter>,
    lookup: HashMap<Vec<u8>, usize>,
    malformed: bool,
    duplicate: bool,
}
impl Parameters {
    fn get(&self, key: &[u8]) -> Option<&Parameter> {
        self.lookup.get(key).map(|&index| &self.values[index])
    }

    /// Match mime.ParseMediaType's RFC2231 resolution for ordinary parameters.
    fn standard_value(&self, key: &[u8]) -> Option<Vec<u8>> {
        let plain = self.get(key).map(|parameter| parameter.value.clone());
        let mut encoded = key.to_vec();
        encoded.push(b'*');
        if let Some(parameter) = self.get(&encoded) {
            return extended_value(&parameter.value).or(plain);
        }
        let mut output = Vec::new();
        let mut present = false;
        for index in 0..self.values.len() {
            let mut piece = encoded.clone();
            piece.extend_from_slice(index.to_string().as_bytes());
            if let Some(parameter) = self.get(&piece) {
                output.extend_from_slice(&parameter.value);
            } else {
                piece.push(b'*');
                let Some(parameter) = self.get(&piece) else {
                    break;
                };
                let decoded = if index == 0 {
                    extended_value(&parameter.value)
                } else {
                    let (value, invalid) = percent_decode(&parameter.value);
                    (!invalid).then_some(value)
                };
                // Go keeps later continuation pieces even when this encoded
                // piece is invalid; omitting them could hide a dangerous name.
                if let Some(decoded) = decoded {
                    output.extend_from_slice(&decoded);
                }
            }
            present = true;
        }
        if present {
            Some(output)
        } else {
            plain
        }
    }
}

fn extended_value(value: &[u8]) -> Option<Vec<u8>> {
    let mut parts = value.splitn(3, |&byte| byte == b'\'');
    let charset = parts.next()?;
    let _language = parts.next()?;
    let value = parts.next()?;
    if !charset.eq_ignore_ascii_case(b"utf-8") && !charset.eq_ignore_ascii_case(b"us-ascii") {
        return None;
    }
    let (value, invalid) = percent_decode(value);
    (!invalid).then_some(value)
}

/// Coraza's independent raw-parameter reading unquotes every quoted pair,
/// including backslashes that mime.ParseMediaType preserves for Windows paths.
fn raw_parameter_value(parameter: &Parameter) -> Vec<u8> {
    let Some(raw) = &parameter.raw_quoted else {
        return parameter.value.clone();
    };
    let mut value = Vec::with_capacity(raw.len());
    let mut position = 0;
    while position < raw.len() {
        if raw[position] == b'\\' && position + 1 < raw.len() {
            position += 1;
        }
        value.push(raw[position]);
        position += 1;
    }
    value
}

fn trim(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &value[start..end]
}
fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}
fn special(byte: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&byte)
}

fn parameters(raw: &[u8]) -> Parameters {
    let mut parsed = Parameters::default();
    let end = raw
        .iter()
        .position(|&byte| byte == b';')
        .unwrap_or(raw.len());
    parsed.media = trim(&raw[..end]).to_ascii_lowercase();
    let valid_media = parsed
        .media
        .split(|&byte| byte == b'/')
        .all(|piece| !piece.is_empty() && piece.iter().all(|&byte| token(byte)));
    if !valid_media || parsed.media.iter().filter(|&&byte| byte == b'/').count() > 1 {
        parsed.malformed = true;
    }
    let mut position = end;
    while position < raw.len() {
        if raw[position] != b';' {
            parsed.malformed = true;
            break;
        }
        position += 1;
        while raw.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        if position == raw.len() {
            break;
        }
        let start = position;
        while raw.get(position).is_some_and(|&byte| token(byte)) {
            position += 1;
        }
        if start == position {
            parsed.malformed = true;
            break;
        }
        let key = raw[start..position].to_ascii_lowercase();
        while raw.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        if raw.get(position) != Some(&b'=') {
            parsed.malformed = true;
            break;
        }
        position += 1;
        while raw.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        let quoted = raw.get(position) == Some(&b'"');
        let quoted_start = position + 1;
        let mut value = Vec::new();
        if quoted {
            position += 1;
            let mut closed = false;
            while let Some(&byte) = raw.get(position) {
                position += 1;
                if byte == b'"' {
                    closed = true;
                    break;
                }
                if matches!(byte, b'\r' | b'\n') {
                    break;
                }
                if byte == b'\\' && raw.get(position).is_some_and(|&byte| special(byte)) {
                    value.push(raw[position]);
                    position += 1;
                } else {
                    value.push(byte);
                }
            }
            if !closed {
                parsed.malformed = true;
                break;
            }
        } else {
            let start = position;
            while raw.get(position).is_some_and(|&byte| token(byte)) {
                position += 1;
            }
            if start == position {
                parsed.malformed = true;
                break;
            }
            value.extend_from_slice(&raw[start..position]);
        }
        if let Some(&index) = parsed.lookup.get(&key) {
            parsed.duplicate = true;
            if parsed.values[index].value != value {
                parsed.malformed = true;
            }
        } else {
            parsed.lookup.insert(key.clone(), parsed.values.len());
        }
        let raw_quoted = quoted.then(|| raw[quoted_start..position - 1].to_vec());
        parsed.values.push(Parameter {
            key,
            value,
            quoted,
            raw_quoted,
        });
        while raw.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        if position < raw.len() && raw[position] != b';' {
            parsed.malformed = true;
            break;
        }
    }
    parsed
}

#[derive(Clone, Copy)]
struct Boundary {
    position: usize,
    after: usize,
    closing: bool,
    crlf: bool,
    terminated: bool,
}
fn boundary_at(body: &[u8], delimiter: &[u8], position: usize) -> Option<Boundary> {
    if position > 0 && body[position - 1] != b'\n' {
        return None;
    }
    let mut after = position + delimiter.len();
    let closing = body.get(after..)?.starts_with(b"--");
    if closing {
        after += 2;
    }
    while matches!(body.get(after), Some(b' ' | b'\t')) {
        after += 1;
    }
    let crlf = body.get(after..)?.starts_with(b"\r\n");
    let terminated = crlf || body.get(after) == Some(&b'\n');
    if crlf {
        after += 2;
    } else if body.get(after) == Some(&b'\n') {
        after += 1;
    } else if !closing || after != body.len() {
        return None;
    }
    Some(Boundary {
        position,
        after,
        closing,
        crlf,
        terminated,
    })
}
fn next_boundary(
    body: &[u8],
    delimiter: &[u8],
    finder: &memchr::memmem::Finder<'_>,
    start: usize,
    style: Option<bool>,
) -> Option<Boundary> {
    let mut from = start;
    while from < body.len() {
        let position = from + finder.find(&body[from..])?;
        if let Some(boundary) = boundary_at(body, delimiter, position) {
            let matching_prefix = style
                .is_none_or(|crlf| !crlf || position == 0 || body[..position].ends_with(b"\r\n"));
            let matching_suffix = style.is_none_or(|crlf| {
                boundary.crlf == crlf || (boundary.closing && !boundary.terminated)
            });
            if matching_prefix && matching_suffix {
                return Some(boundary);
            }
        }
        from = position + delimiter.len();
    }
    None
}

#[derive(Debug)]
enum HeaderError {
    Eof,
    Malformed(&'static str),
}
fn line(body: &[u8], position: usize) -> (&[u8], usize, bool) {
    if let Some(end) = memchr::memchr(b'\n', &body[position..]) {
        let end = position + end;
        let value = body[position..end]
            .strip_suffix(b"\r")
            .unwrap_or(&body[position..end]);
        (value, end + 1, true)
    } else {
        (&body[position..], body.len(), false)
    }
}
fn canonical_name(name: &[u8]) -> Result<Vec<u8>, HeaderError> {
    if name.is_empty() || name.iter().any(|&byte| !token(byte) && byte != b' ') {
        return Err(HeaderError::Malformed("invalid multipart header name"));
    }
    let mut name = name.to_vec();
    if !name.contains(&b' ') {
        let mut upper = true;
        for byte in &mut name {
            *byte = if upper {
                byte.to_ascii_uppercase()
            } else {
                byte.to_ascii_lowercase()
            };
            upper = *byte == b'-';
        }
    }
    Ok(name)
}
type Headers = Vec<(Vec<u8>, Vec<u8>)>;
fn read_headers(body: &[u8], mut position: usize) -> Result<(Headers, usize), HeaderError> {
    let mut headers: Headers = Vec::new();
    let start = position;
    loop {
        if position == body.len() {
            return Err(HeaderError::Eof);
        }
        let (raw, after, terminated) = line(body, position);
        position = after;
        if raw.is_empty() {
            if !terminated {
                return Err(HeaderError::Eof);
            }
            return Ok((headers, position));
        }
        // Validate before trimming and unfolding, which must not erase invalid
        // control bytes at the beginning/end of a value or continuation line.
        if raw
            .iter()
            .any(|&byte| (byte < 32 && byte != b'\t') || byte == 127)
        {
            return Err(HeaderError::Malformed("invalid multipart header value"));
        }
        if raw.starts_with(b" ") || raw.starts_with(b"\t") {
            let Some((_, value)) = headers.last_mut() else {
                return Err(HeaderError::Malformed(
                    "multipart header starts with whitespace",
                ));
            };
            value.push(b' ');
            value.extend_from_slice(trim(raw));
        } else {
            let Some(colon) = raw.iter().position(|&byte| byte == b':') else {
                return Err(HeaderError::Malformed(
                    "multipart header is missing a colon",
                ));
            };
            let name = canonical_name(&raw[..colon])?;
            let value = trim(&raw[colon + 1..]);
            headers.push((name, value.to_vec()));
        }
        if headers.len() > 10000 || position - start > 10 * 1024 * 1024 {
            return Err(HeaderError::Malformed(
                "multipart headers exceed processing limits",
            ));
        }
        if !terminated {
            return Err(HeaderError::Eof);
        }
    }
}
fn percent_decode(value: &[u8]) -> (Vec<u8>, bool) {
    let mut output = Vec::with_capacity(value.len());
    let mut invalid = false;
    let mut position = 0;
    while position < value.len() {
        if value[position] == b'%' {
            if let Some(pair) = value.get(position + 1..position + 3) {
                if let (Some(hi), Some(lo)) = (hex(pair[0]), hex(pair[1])) {
                    output.push(hi * 16 + lo);
                    position += 3;
                    continue;
                }
            }
            invalid = true;
        }
        output.push(value[position]);
        position += 1;
    }
    (output, invalid)
}
fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// The reference Go quotedprintable.Reader's permissive decoding rules.
fn quoted_printable(content: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(content.len());
    for raw in content.split_inclusive(|&byte| byte == b'\n') {
        let has_lf = raw.ends_with(b"\n");
        let has_crlf = raw.ends_with(b"\r\n");
        // Go's decoder reads one line with a 4096-byte bufio.Reader.
        if raw.len() > 4096 || (raw.len() == 4096 && !has_lf) {
            return Err("quoted-printable line exceeds the reference reader buffer".into());
        }
        let end = raw
            .iter()
            .rposition(|byte| !matches!(byte, b'\n' | b'\r' | b' ' | b'\t'))
            .map_or(0, |position| position + 1);
        let mut line = &raw[..end];
        let soft = line.ends_with(b"=");
        if soft {
            line = &line[..line.len() - 1];
            let after = &raw[end..];
            let suffix = after
                .iter()
                .position(|byte| !matches!(byte, b' ' | b'\t'))
                .map_or(&b""[..], |position| &after[position..]);
            let valid_suffix = suffix.starts_with(b"\n")
                || suffix.starts_with(b"\r\n")
                || (suffix.is_empty() && !line.is_empty());
            if !valid_suffix {
                return Err("invalid bytes after quoted-printable soft break".into());
            }
        }
        let mut position = 0;
        while position < line.len() {
            let byte = line[position];
            if byte == b'=' {
                if let Some(pair) = line.get(position + 1..position + 3) {
                    if let (Some(hi), Some(lo)) = (hex(pair[0]), hex(pair[1])) {
                        output.push(hi * 16 + lo);
                        position += 3;
                        continue;
                    }
                }
                // Malformed hex inside a line is a literal '=' in Go.
                if !line
                    .get(position + 1)
                    .is_some_and(|byte| !matches!(byte, b'\r' | b'\n'))
                {
                    return Err("truncated quoted-printable escape".into());
                }
            } else if (byte < 32 && !matches!(byte, b'\t' | b'\r' | b'\n')) || byte == 127 {
                return Err("invalid unescaped quoted-printable control byte".into());
            }
            output.push(byte);
            position += 1;
        }
        if !soft && has_lf {
            if has_crlf {
                output.push(b'\r');
            }
            output.push(b'\n');
        }
    }
    Ok(output)
}

fn process_part(
    parsed: &mut Multipart,
    mut headers: Headers,
    content: &[u8],
    upload_dir: Option<&std::path::Path>,
) {
    // mime/multipart.NextPart decodes quoted-printable and removes this
    // header before exposing the part. Other encodings remain opaque.
    let transfer_decoded = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(b"Content-Transfer-Encoding"))
        .is_some_and(|(_, value)| value.eq_ignore_ascii_case(b"quoted-printable"));
    if transfer_decoded {
        headers.retain(|(name, _)| !name.eq_ignore_ascii_case(b"Content-Transfer-Encoding"));
    }
    let mut seen = HashSet::new();
    if headers.iter().any(|(name, _)| !seen.insert(name.clone())) {
        parsed.duplicate = true;
        parsed.strict = true;
    }
    let disposition = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(b"Content-Disposition"));
    let parameters = disposition
        .filter(|(_, value)| !value.is_empty())
        .map(|(_, value)| parameters(value));
    let valid = parameters
        .as_ref()
        .filter(|parameters| !parameters.malformed);
    if let Some(parameters) = &parameters {
        if parameters.malformed {
            parsed.strict = true;
            parsed.duplicate |= parameters.duplicate;
        }
    }
    let name = valid
        .filter(|parameters| parameters.media == b"form-data")
        .and_then(|parameters| parameters.standard_value(b"name"))
        .unwrap_or_default();
    for (key, value) in headers {
        let mut header = key;
        header.extend_from_slice(b": ");
        header.extend_from_slice(&value);
        parsed.headers.add_bytes(name.clone(), header);
    }
    parsed.names.add_bytes(name.clone(), name.clone());
    let mut filename = valid
        .and_then(|parameters| parameters.standard_value(b"filename"))
        .unwrap_or_default();
    let mut alternative = Vec::new();
    if let Some(parameters) = valid {
        let continuation = parameters.values.iter().any(|parameter| {
            parameter
                .key
                .strip_prefix(b"filename*")
                .is_some_and(|suffix| {
                    let suffix = suffix.strip_suffix(b"*").unwrap_or(suffix);
                    !suffix.is_empty() && suffix.iter().all(u8::is_ascii_digit)
                })
        });
        if continuation {
            parsed.strict = true;
            if let Some(plain) = parameters.get(b"filename") {
                let raw = raw_parameter_value(plain);
                if !filename.is_empty() && filename != raw {
                    alternative = filename;
                }
                filename = raw;
            }
        }
        if let Some(extended) = parameters.get(b"filename*") {
            if extended.quoted {
                parsed.invalid_quoting = true;
                parsed.strict = true;
            }
            let raw = raw_parameter_value(extended);
            let mut split = raw.splitn(3, |&byte| byte == b'\'');
            if let (Some(charset), Some(language), Some(value)) =
                (split.next(), split.next(), split.next())
            {
                let (decoded, invalid_escape) = percent_decode(value);
                if invalid_escape {
                    parsed.strict = true;
                }
                alternative = parameters
                    .get(b"filename")
                    .map(raw_parameter_value)
                    .filter(|plain| !plain.is_empty() && plain != &decoded)
                    .unwrap_or_default();
                filename = decoded;
                parsed.charsets.add_bytes(name.clone(), charset);
                parsed.languages.add_bytes(name.clone(), language);
            } else {
                parsed.strict = true;
            }
        }
    }
    if !filename.is_empty() {
        parsed.filenames.add_bytes(name.clone(), filename.clone());
    }
    if !alternative.is_empty() && alternative != filename {
        parsed
            .filenames
            .add_bytes(name.clone(), alternative.clone());
    }
    if filename.is_empty() && !alternative.is_empty() {
        filename = std::mem::take(&mut alternative);
    }
    let decoded = if transfer_decoded {
        match quoted_printable(content) {
            Ok(value) => Some(value),
            Err(error) => {
                parsed.strict = true;
                parsed.error = Some(error);
                return;
            }
        }
    } else {
        None
    };
    let content = decoded.as_deref().unwrap_or(content);
    parsed.combined_size += content.len();
    if filename.is_empty() {
        parsed.fields.add_bytes(name, content);
    } else {
        if let Some(uploads) = parsed.uploads.as_mut() {
            if let Err(error) = uploads.store(content, upload_dir) {
                parsed.strict = true;
                parsed.error = Some(format!("cannot store multipart file: {error}"));
                return;
            }
        }
        parsed.file_names.add_bytes(b"".as_slice(), name);
        parsed
            .file_sizes
            .set_bytes(filename.clone(), content.len().to_string());
        parsed.files.add_bytes(b"".as_slice(), filename.clone());
        if !alternative.is_empty() && alternative != filename {
            parsed
                .file_sizes
                .set_bytes(alternative.clone(), content.len().to_string());
            parsed.files.add_bytes(b"".as_slice(), alternative);
        }
    }
}

pub(super) fn parse(
    body: &[u8],
    content_type: &[u8],
    partial: bool,
    store_uploads: bool,
    upload_dir: Option<&std::path::Path>,
) -> Multipart {
    let mut parsed = Multipart {
        uploads: store_uploads.then(UploadedFiles::default),
        ..Default::default()
    };
    let params = parameters(content_type);
    let boundary = params
        .standard_value(b"boundary")
        .filter(|value| !value.is_empty());
    if params.malformed || !params.media.starts_with(b"multipart/") || boundary.is_none() {
        parsed.strict = true;
        parsed.error = Some("multipart Content-Type has no valid boundary".into());
        return parsed;
    }
    parsed.has_boundary = true;
    let mut delimiter = b"--".to_vec();
    delimiter.extend_from_slice(&boundary.unwrap());
    let finder = memchr::memmem::Finder::new(&delimiter);
    let Some(mut boundary) = next_boundary(body, &delimiter, &finder, 0, None) else {
        if !partial {
            parsed.strict = true;
            parsed.error = Some("multipart body has no opening boundary".into());
        }
        return parsed;
    };
    let style = boundary.crlf;
    while !boundary.closing {
        let (headers, start) = match read_headers(body, boundary.after) {
            Ok(value) => value,
            Err(HeaderError::Eof) if partial => break,
            Err(error) => {
                parsed.strict = true;
                parsed.error = Some(match error {
                    HeaderError::Eof => "multipart headers ended unexpectedly".into(),
                    HeaderError::Malformed(error) => error.into(),
                });
                break;
            }
        };
        match next_boundary(body, &delimiter, &finder, start, Some(style)) {
            Some(next) => {
                let framing = if style { 2 } else { 1 };
                let end = next.position.saturating_sub(framing).max(start);
                process_part(&mut parsed, headers, &body[start..end], upload_dir);
                if parsed.error.is_some() {
                    break;
                }
                boundary = next;
            }
            None => {
                process_part(&mut parsed, headers, &body[start..], upload_dir);
                if !partial {
                    parsed.strict = true;
                }
                break;
            }
        }
    }
    parsed
}
