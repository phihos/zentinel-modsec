//! Coraza 3.8.1's streaming XML value contract, without external resolution.
use super::collection::HashMapCollection;
use super::xml_entities::HTML_ENTITIES;
use quick_xml::events::Event;

const MAX_XML_VALUES: usize = 4096;
const MAX_XML_DEPTH: usize = 64;

pub(super) fn parse(body: &[u8]) -> Result<(HashMapCollection, Option<String>), String> {
    let mut reader = quick_xml::Reader::from_reader(body);
    // encoding/xml.Strict=false synthesizes ancestor closes; manage that stack
    // here rather than letting quick-xml reject a different literal end name.
    reader.config_mut().check_end_names = false;
    reader.config_mut().allow_unmatched_ends = true;
    reader.config_mut().allow_dangling_amp = true;
    let mut open: Vec<String> = Vec::new();
    let mut attributes = Vec::new();
    let mut contents = Vec::new();
    let mut text = String::new();
    let mut suppressed_entity = None;
    let mut count = 0;
    let mut buf = Vec::new();
    loop {
        let event = reader.read_event_into(&mut buf);
        match event {
            Ok(Event::Text(value)) => {
                let value = value.xml10_content().map_err(|error| error.to_string())?;
                if value.contains("]]>") {
                    return Err("unescaped ]]> in XML text".into());
                }
                validate_characters(&value)?;
                text.push_str(&value);
            }
            Ok(Event::GeneralRef(value)) => {
                let name = value.decode().map_err(|error| error.to_string())?;
                let resolved = resolve_reference(&name, &mut suppressed_entity);
                validate_characters(&resolved)?;
                text.push_str(&resolved);
            }
            other => {
                flush_text(&mut text, &mut contents, &mut count)?;
                let empty = matches!(&other, Ok(Event::Empty(_)));
                match other {
                    Ok(Event::Start(value)) | Ok(Event::Empty(value)) => {
                        if open.last().is_some_and(|name| auto_closes(name)) {
                            open.pop();
                        }
                        if open.len() >= MAX_XML_DEPTH {
                            return Err(format!(
                                "XML body exceeded {MAX_XML_DEPTH} levels of nesting"
                            ));
                        }
                        let name = std::str::from_utf8(value.name().as_ref())
                            .map_err(|error| error.to_string())?
                            .to_string();
                        read_attributes(
                            value.attributes_raw(),
                            &mut attributes,
                            &mut count,
                            &mut suppressed_entity,
                        )?;
                        if !empty {
                            open.push(name);
                        }
                    }
                    Ok(Event::End(value)) => {
                        let name = std::str::from_utf8(value.name().as_ref())
                            .map_err(|error| error.to_string())?
                            .to_string();
                        if open.last().is_some_and(|last| {
                            auto_closes(last) && !last.eq_ignore_ascii_case(&name)
                        }) {
                            open.pop();
                        }
                        let Some(position) = open.iter().rposition(|existing| existing == &name)
                        else {
                            return Err(format!("unexpected XML end element </{name}>"));
                        };
                        open.truncate(position);
                    }
                    Ok(Event::CData(value)) => {
                        let value = value.xml10_content().map_err(|error| error.to_string())?;
                        validate_characters(&value)?;
                        let value = value.trim();
                        if !value.is_empty() {
                            push(&mut contents, value.into(), &mut count)?;
                        }
                    }
                    Ok(Event::Decl(value)) => {
                        if let Some(encoding) = value.encoding() {
                            let encoding = encoding.map_err(|error| error.to_string())?;
                            if !encoding.eq_ignore_ascii_case(b"utf-8") {
                                return Err("XML body declares an unsupported encoding".into());
                            }
                        }
                    }
                    Ok(Event::Eof) => break,
                    Ok(_) => {} // comments, processing instructions, and DTDs are not values
                    Err(quick_xml::Error::Syntax(
                        quick_xml::errors::SyntaxError::UnclosedCData,
                    )) => return Err("unexpected EOF in XML CDATA section".into()),
                    // The pinned reference explicitly accepts unexpected EOF,
                    // including incomplete markup, and retains preceding tokens.
                    Err(quick_xml::Error::Syntax(_)) => break,
                    Err(error) => return Err(format!("XML parsing error: {error}")),
                }
            }
        }
        buf.clear();
    }
    let mut values = HashMapCollection::new();
    // Coraza publishes all attributes followed by all text tokens.
    for value in attributes {
        values.add("//@*".into(), value);
    }
    for value in contents {
        values.add("/*".into(), value);
    }
    Ok((values, suppressed_entity))
}

fn flush_text(
    text: &mut String,
    contents: &mut Vec<String>,
    count: &mut usize,
) -> Result<(), String> {
    let value = text.trim();
    if !value.is_empty() {
        push(contents, value.into(), count)?;
    }
    text.clear();
    Ok(())
}

fn push(values: &mut Vec<String>, value: String, count: &mut usize) -> Result<(), String> {
    if *count >= MAX_XML_VALUES {
        return Err(format!(
            "XML body exceeded {MAX_XML_VALUES} extracted values"
        ));
    }
    *count += 1;
    values.push(value);
    Ok(())
}

fn auto_closes(name: &str) -> bool {
    let local = name.rsplit(':').next().unwrap_or(name);
    [
        "basefont", "br", "area", "link", "img", "param", "hr", "input", "col", "frame", "isindex",
        "base", "meta",
    ]
    .iter()
    .any(|name| local.eq_ignore_ascii_case(name))
}

fn validate_characters(value: &str) -> Result<(), String> {
    if let Some(character) = value.chars().find(|&c| {
        !matches!(c as u32,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
    }) {
        return Err(format!("illegal XML character U+{:04X}", character as u32));
    }
    Ok(())
}

fn resolve_reference(name: &str, suppressed_entity: &mut Option<String>) -> String {
    let numeric = name.strip_prefix('#').and_then(|digits| {
        let (digits, base) = digits
            .strip_prefix('x')
            .map_or((digits, 10), |hex| (hex, 16));
        u64::from_str_radix(digits, base)
            .ok()
            .filter(|value| *value <= 0x10FFFF)
    });
    if let Some(value) = numeric {
        return char::from_u32(value as u32)
            .unwrap_or(char::REPLACEMENT_CHARACTER)
            .to_string();
    }
    if let Some(value) = quick_xml::escape::resolve_predefined_entity(name) {
        return value.into();
    }
    if let Some(value) = HTML_ENTITIES.get(name) {
        return value.to_string();
    }
    // Keep the literal visible, but preserve the engine's stronger policy:
    // suppressing custom content must also set REQBODY_ERROR. No DTD, file,
    // or network content is ever resolved.
    suppressed_entity.get_or_insert_with(|| name.into());
    format!("&{name};")
}

fn decode_attribute(raw: &[u8], suppressed_entity: &mut Option<String>) -> Result<String, String> {
    let value = std::str::from_utf8(raw).map_err(|error| error.to_string())?;
    if value.contains('<') {
        return Err("unescaped < in XML attribute".into());
    }
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let mut result = String::new();
    let mut remaining = normalized.as_str();
    while let Some((before, after)) = remaining.split_once('&') {
        result.push_str(before);
        match after
            .char_indices()
            .find(|(_, c)| *c == ';' || *c == '&' || c.is_whitespace())
        {
            Some((position, ';')) => {
                result.push_str(&resolve_reference(&after[..position], suppressed_entity));
                remaining = &after[position + 1..];
            }
            Some(_) => {
                // A bare ampersand must not swallow the next valid reference.
                result.push('&');
                remaining = after;
            }
            None => {
                result.push('&');
                remaining = after;
                break;
            }
        }
    }
    result.push_str(remaining);
    validate_characters(&result)?;
    Ok(result)
}

fn read_attributes(
    raw: &[u8],
    attributes: &mut Vec<String>,
    count: &mut usize,
    suppressed_entity: &mut Option<String>,
) -> Result<(), String> {
    let mut position = 0;
    while position < raw.len() {
        while raw.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        let start = position;
        while raw
            .get(position)
            .is_some_and(|&byte| !byte.is_ascii_whitespace() && byte != b'=')
        {
            position += 1;
        }
        if start == position {
            break;
        }
        let name = std::str::from_utf8(&raw[start..position]).map_err(|error| error.to_string())?;
        while raw.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        let value = if raw.get(position) == Some(&b'=') {
            position += 1;
            while raw.get(position).is_some_and(u8::is_ascii_whitespace) {
                position += 1;
            }
            let quote = raw.get(position).copied();
            if matches!(quote, Some(b'\'' | b'"')) {
                position += 1;
                let start = position;
                while raw.get(position).is_some_and(|&byte| Some(byte) != quote) {
                    position += 1;
                }
                if position == raw.len() {
                    return Err("unclosed XML attribute".into());
                }
                let value = decode_attribute(&raw[start..position], suppressed_entity)?;
                position += 1;
                value
            } else {
                let start = position;
                while raw
                    .get(position)
                    .is_some_and(|byte| !byte.is_ascii_whitespace())
                {
                    position += 1;
                }
                decode_attribute(&raw[start..position], suppressed_entity)?
            }
        } else {
            // encoding/xml.Strict=false represents a bare attribute by its
            // local name rather than silently discarding it.
            name.rsplit(':').next().unwrap_or(name).to_string()
        };
        push(attributes, value, count)?;
    }
    Ok(())
}
