//! Response data for variable resolution.

use super::collection::HashMapCollection;

/// Response data container.
#[derive(Debug, Clone, Default)]
pub struct ResponseData {
    /// HTTP status code.
    pub status: u16,
    /// Response protocol.
    pub protocol: String,
    /// Response headers.
    pub headers: HashMapCollection,
    /// Response body.
    pub body: Vec<u8>,
    /// Acquisition reached the configured response body limit.
    pub outbound_data_error: bool,
    /// Body bytes were made available to phase 4 under the MIME/access policy.
    pub body_inspected: bool,
    /// Content type.
    pub content_type: String,
}

impl ResponseData {
    /// Create new response data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the status code.
    pub fn set_status(&mut self, status: u16) {
        self.status = status;
    }

    /// Set the protocol.
    pub fn set_protocol(&mut self, protocol: &str) {
        self.protocol = protocol.to_string();
    }

    /// Add a response header.
    pub fn add_header(&mut self, name: &str, value: &str) {
        self.add_header_bytes(name.as_bytes(), value.as_bytes());
    }

    /// Add original response bytes, retaining each header name separately from
    /// its normalized lookup key.
    pub fn add_header_bytes(&mut self, name: &[u8], value: &[u8]) {
        self.headers
            .add_named_bytes(name.to_ascii_lowercase(), name, value);
        if name.eq_ignore_ascii_case(b"content-type") {
            self.content_type = super::ByteValue::from(media_type(value)).to_string();
        }
    }

    /// Media type from the last received Content-Type, before parameters.
    pub fn content_type_bytes(&self) -> &[u8] {
        self.headers
            .last_value_bytes(b"content-type")
            .map_or_else(|| self.content_type.as_bytes(), media_type)
    }

    /// Append to response body.
    pub fn append_body(&mut self, data: &[u8]) {
        self.body.extend_from_slice(data);
    }

    /// Get body as string.
    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Get body length.
    pub fn body_length(&self) -> usize {
        self.body.len()
    }

    /// Bytes visible through RESPONSE_BODY after its phase's access checks.
    pub fn body_variable_bytes(&self) -> &[u8] {
        if self.body_inspected {
            &self.body
        } else {
            b""
        }
    }
}

fn media_type(value: &[u8]) -> &[u8] {
    value.split(|&byte| byte == b';').next().unwrap_or_default()
}
