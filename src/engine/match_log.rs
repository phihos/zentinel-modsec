//! Transactions retain matched bytes immediately. Audit consumers request the
//! public byte and text representations together, sometimes between phases.
use std::sync::{Mutex, OnceLock};

use super::transaction::MatchedData;
use crate::variables::ByteValue;

pub(super) struct RawMatch {
    pub rule_id: Option<String>,
    pub variable: ByteValue,
    pub value: ByteValue,
    pub portion: Option<ByteValue>,
}

impl From<RawMatch> for MatchedData {
    fn from(raw: RawMatch) -> Self {
        let present = ByteValue::into_display_and_bytes;
        let (variable, variable_bytes) = present(raw.variable);
        let (value, value_bytes) = present(raw.value);
        let (matched_portion, matched_portion_bytes) = raw.portion.map(present).unzip();
        Self {
            rule_id: raw.rule_id,
            variable,
            value,
            matched_portion,
            variable_bytes,
            value_bytes,
            matched_portion_bytes,
        }
    }
}

#[derive(Default)]
pub(super) struct MatchLog {
    // Recording always has exclusive transaction access and uses get_mut().
    // The first reader takes the raw buffer, leaving only the published form.
    raw: Mutex<Vec<RawMatch>>,
    published: OnceLock<Vec<MatchedData>>,
}

impl MatchLog {
    pub fn extend(&mut self, matches: impl IntoIterator<Item = RawMatch>) {
        if let Some(view) = self.published.get_mut() {
            view.extend(matches.into_iter().map(MatchedData::from));
        } else {
            self.raw.get_mut().unwrap().extend(matches);
        }
    }

    pub fn as_slice(&self) -> &[MatchedData] {
        self.published.get_or_init(|| {
            let raw = std::mem::take(&mut *self.raw.lock().unwrap());
            raw.into_iter().map(MatchedData::from).collect()
        })
    }
}
