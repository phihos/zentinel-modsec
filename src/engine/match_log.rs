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
    fn phase_defaults(ruleset: &CompiledRuleset) -> impl ExactSizeIterator<Item = Self> + '_;
}

impl MatchRecord for (RuleLocation, RawMatch) {
    type View = MatchedData;

    fn phase_defaults(ruleset: &CompiledRuleset) -> impl ExactSizeIterator<Item = Self> + '_ {
        let phase = Phase::RequestHeaders;
        let dispatch = ruleset.dispatch_for_phase(phase);
        let defaults = ruleset.tx_defaults.as_ref().unwrap();
        defaults.counts.iter().map(move |&entry| {
            let (variable, value) = super::initialization::TxDefaults::count_value(dispatch, entry);
            (
                RuleLocation {
                    phase,
                    index: usize::from(entry.0),
                },
                RawMatch {
                    variable,
                    portion: Some(value.clone()),
                    value,
                },
            )
        })
    }

    fn publish(self, ruleset: &CompiledRuleset) -> Self::View {
        self.1.publish(self.0.id(ruleset))
    }
}

impl MatchRecord for RuleLocation {
    type View = String;

    fn phase_defaults(ruleset: &CompiledRuleset) -> impl ExactSizeIterator<Item = Self> + '_ {
        ruleset
            .tx_defaults
            .as_ref()
            .unwrap()
            .ids
            .iter()
            .map(|&index| RuleLocation {
                phase: Phase::RequestHeaders,
                index: usize::from(index),
            })
    }

    fn publish(self, ruleset: &CompiledRuleset) -> String {
        self.id(ruleset)
            .expect("only named rules enter the ID log")
            .to_owned()
    }
}

/// A single named match can borrow its public ID directly from the ruleset.
#[derive(Default)]
pub(super) enum MatchedRules {
    #[default]
    Empty,
    One(RuleLocation),
    Many(MatchLog<RuleLocation>),
}

impl MatchedRules {
    pub fn from_defaults(ids: &[u8]) -> Self {
        match ids {
            [] => Self::Empty,
            [index] => Self::One(RuleLocation {
                phase: Phase::RequestHeaders,
                index: usize::from(*index),
            }),
            _ => Self::Many(MatchLog::with_default_prefix(true)),
        }
    }

    pub fn push(&mut self, ruleset: &CompiledRuleset, next: RuleLocation) {
        match self {
            Self::Empty => *self = Self::One(next),
            Self::One(first) => {
                let mut records = MatchLog::default();
                records.extend(ruleset, [*first, next]);
                *self = Self::Many(records);
            }
            Self::Many(records) => records.extend(ruleset, std::iter::once(next)),
        }
    }

    pub fn as_slice<'a>(&'a self, ruleset: &'a CompiledRuleset, phase: Phase) -> &'a [String] {
        match self {
            Self::Empty => &[],
            Self::One(loc) => ruleset.rules_for_phase(loc.phase)[loc.index].id.as_slice(),
            Self::Many(records) => records.as_slice(ruleset, phase),
        }
    }
}

pub(super) struct MatchLog<T: MatchRecord> {
    // Recording always has exclusive transaction access and uses get_mut().
    // The first reader takes the raw buffer, leaving only the published form.
    raw: Mutex<Vec<T>>,
    default_prefix: bool,
    published: OnceLock<Vec<T::View>>,
}

impl<T: MatchRecord> Default for MatchLog<T> {
    fn default() -> Self {
        Self {
            raw: Default::default(),
            default_prefix: false,
            published: Default::default(),
        }
    }
}

impl<T: MatchRecord> MatchLog<T> {
    pub fn with_default_prefix(default_prefix: bool) -> Self {
        Self {
            default_prefix,
            ..Self::default()
        }
    }

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
            let prefix = self.default_prefix.then(|| T::phase_defaults(ruleset));
            let len = raw.len() + prefix.as_ref().map_or(0, ExactSizeIterator::len);
            // An early reader may append matches in subsequent phases. Include
            // the replayed prefix when reserving room for that growth.
            let capacity = if phase == Phase::Logging {
                len
            } else if self.default_prefix {
                len.next_power_of_two().max(4)
            } else {
                raw.capacity()
            };
            let mut published = Vec::with_capacity(capacity);
            if let Some(prefix) = prefix {
                published.extend(prefix.map(|item| item.publish(ruleset)));
            }
            published.extend(raw.into_iter().map(|item| item.publish(ruleset)));
            published
        })
    }
}
