//! Transactions retain matched bytes immediately. Audit consumers request the
//! public byte and text representations together, sometimes between phases.
use std::sync::{Mutex, OnceLock};

use super::{phase::Phase, ruleset::CompiledRuleset, transaction::MatchedData};
use crate::variables::ByteValue;

pub(super) struct RawMatch {
    pub variable: ByteValue,
    pub value: ByteValue,
    pub portion: Option<ByteValue>,
}

/// A transaction keeps its immutable compiled ruleset alive for every audit read.
#[derive(Clone, Copy)]
pub(super) struct RuleLocation {
    pub phase: Phase,
    pub index: usize,
}

impl RuleLocation {
    fn id(self, ruleset: &CompiledRuleset) -> Option<&str> {
        ruleset.rules_for_phase(self.phase)[self.index]
            .id
            .as_deref()
    }
}

impl RawMatch {
    fn publish(self, id: Option<&str>) -> MatchedData {
        let present = ByteValue::into_display_and_bytes;
        let (variable, variable_bytes) = present(self.variable);
        let (value, value_bytes) = present(self.value);
        let (matched_portion, matched_portion_bytes) = self.portion.map(present).unzip();
        MatchedData {
            rule_id: id.map(str::to_owned),
            variable,
            value,
            matched_portion,
            variable_bytes,
            value_bytes,
            matched_portion_bytes,
        }
    }
}

/// Produce an owned public view from the immutable ruleset and match-time data.
pub(super) trait MatchRecord {
    type View;
    fn publish(self, ruleset: &CompiledRuleset) -> Self::View;
}

impl MatchRecord for (RuleLocation, RawMatch) {
    type View = MatchedData;

    fn publish(self, ruleset: &CompiledRuleset) -> Self::View {
        self.1.publish(self.0.id(ruleset))
    }
}

impl MatchRecord for RuleLocation {
    type View = String;

    fn publish(self, ruleset: &CompiledRuleset) -> String {
        self.id(ruleset)
            .expect("only named rules enter the ID log")
            .to_owned()
    }
}

pub(super) struct MatchLog<T: MatchRecord> {
    // Recording always has exclusive transaction access and uses get_mut().
    // The first reader takes the raw buffer, leaving only the published form.
    raw: Mutex<Vec<T>>,
    published: OnceLock<Vec<T::View>>,
}

impl<T: MatchRecord> Default for MatchLog<T> {
    fn default() -> Self {
        Self {
            raw: Default::default(),
            published: Default::default(),
        }
    }
}

impl<T: MatchRecord> MatchLog<T> {
    pub fn extend(&mut self, ruleset: &CompiledRuleset, matches: impl IntoIterator<Item = T>) {
        if let Some(view) = self.published.get_mut() {
            view.extend(matches.into_iter().map(|item| item.publish(ruleset)));
        } else {
            self.raw.get_mut().unwrap().extend(matches);
        }
    }

    pub fn as_slice(&self, ruleset: &CompiledRuleset, phase: Phase) -> &[T::View] {
        self.published.get_or_init(|| {
            let raw = std::mem::take(&mut *self.raw.lock().unwrap());
            // Reading between phases leaves room for later matches.
            let capacity = if phase == Phase::Logging {
                raw.len()
            } else {
                raw.capacity()
            };
            let mut published = Vec::with_capacity(capacity);
            published.extend(raw.into_iter().map(|item| item.publish(ruleset)));
            published
        })
    }
}
