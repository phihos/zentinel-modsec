//! Byte-oriented multipart values and strict parsing diagnostics.
use super::collection::HashMapCollection;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(super) struct Multipart {
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

#[derive(Clone)]
struct Parameter {
    key: Vec<u8>,
    value: Vec<u8>,
    quoted: bool,
}
#[derive(Default)]
struct Parameters {
    media: Vec<u8>,
    values: Vec<Parameter>,
    malformed: bool,
    duplicate: bool,
}
impl Parameters {
    fn get(&self, key: &[u8]) -> Option<&Parameter> {
        self.values.iter().find(|parameter| parameter.key == key)
    }
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
    let mut seen: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
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
        if let Some(previous) = seen.get(&key) {
            parsed.duplicate = true;
            if previous != &value {
                parsed.malformed = true;
            }
        } else {
            seen.insert(key.clone(), value.clone());
        }
        parsed.values.push(Parameter { key, value, quoted });
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
            if value
                .iter()
                .any(|&byte| (byte < 32 && byte != b'\t') || byte == 127)
            {
                return Err(HeaderError::Malformed("invalid multipart header value"));
            }
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
