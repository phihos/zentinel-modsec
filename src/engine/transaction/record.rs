//! What a transaction keeps of a match until somebody reads it.
//!
//! A matched rule's id and its message are copies of what the ruleset
//! already holds. A transaction keeps where the rule sits instead and makes
//! the copies when [`Transaction::matched_rules`] or
//! [`Transaction::messages`] is first called, so a caller that reads neither
//! pays for neither.
//!
//! [`Transaction::matched_rules`]: super::Transaction::matched_rules
//! [`Transaction::messages`]: super::Transaction::messages

use super::MatchedData;
use crate::engine::intervention::RuleMessage;
use crate::engine::phase::Phase;
use crate::engine::ruleset::{CompiledRule, CompiledRuleset};
use std::sync::{Mutex, OnceLock};

/// Where a rule sits in its ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::engine) struct RuleAt {
    pub(super) phase: Phase,
    pub(super) index: usize,
}

impl RuleAt {
    fn rule(self, ruleset: &CompiledRuleset) -> Option<&CompiledRule> {
        ruleset.rules_for_phase(self.phase).get(self.index)
    }
}

/// Something a transaction records for a match and publishes on demand.
pub(in crate::engine) trait Record: Clone {
    /// What a caller reads.
    type Published;

    /// What a caller reads for this record, made from the rule in `ruleset`.
    fn publish(&self, ruleset: &CompiledRuleset) -> Option<Self::Published>;
}

/// A matched rule, published as its id.
impl Record for RuleAt {
    type Published = String;

    fn publish(&self, ruleset: &CompiledRuleset) -> Option<String> {
        self.rule(ruleset)?.id.clone()
    }
}

/// The message of a matched rule: the rule, and those of its texts that had
/// macros to expand at the match. A text without one is as the rule has it.
#[derive(Debug, Clone)]
pub(in crate::engine) struct MessageRecord {
    pub(super) rule: RuleAt,
    pub(super) msg: Option<String>,
    pub(super) data: Option<String>,
}

impl Record for MessageRecord {
    type Published = RuleMessage;

    fn publish(&self, ruleset: &CompiledRuleset) -> Option<RuleMessage> {
        let rule = &self.rule.rule(ruleset)?.metadata;
        Some(RuleMessage {
            rule_id: rule.id.clone(),
            rev: rule.rev.clone(),
            msg: self.msg.clone().or_else(|| rule.msg.clone()),
            data: self.data.clone().or_else(|| rule.logdata.clone()),
            severity: rule.severity,
            ver: rule.ver.clone(),
            maturity: rule.maturity,
            accuracy: rule.accuracy,
            tags: rule.tags.clone(),
        })
    }
}

/// The records of a transaction, in order, and what was published of them.
pub(in crate::engine) struct Records<R: Record> {
    /// The records nobody has read yet. Unused once `published` is set.
    pending: Vec<R>,
    /// Every record as published, from the first read on.
    published: OnceLock<Vec<R::Published>>,
}

impl<R: Record> Default for Records<R> {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            published: OnceLock::new(),
        }
    }
}

impl<R: Record> Records<R> {
    /// Add a record of a rule of `ruleset`.
    pub(super) fn push(&mut self, record: R, ruleset: &CompiledRuleset) {
        match self.published.get_mut() {
            Some(published) => published.extend(record.publish(ruleset)),
            None => self.pending.push(record),
        }
    }

    /// Every record so far, published.
    pub(super) fn as_slice(&self, ruleset: &CompiledRuleset) -> &[R::Published] {
        self.published.get_or_init(|| {
            let mut published = Vec::with_capacity(self.pending.len());
            published.extend(
                self.pending
                    .iter()
                    .filter_map(|record| record.publish(ruleset)),
            );
            published
        })
    }

    /// The records of a transaction nobody has read from.
    pub(super) fn into_pending(self) -> Vec<R> {
        debug_assert!(self.published.get().is_none());
        self.pending
    }

    /// Start over from `pending`.
    pub(super) fn restore(&mut self, pending: &[R]) {
        self.pending.clear();
        self.pending.extend_from_slice(pending);
        self.published = OnceLock::new();
    }
}

/// Completed records from phase initialization live in the ruleset. A transaction
/// owns the unfinished last record and every record produced by later rules.
#[derive(Default)]
pub(super) struct MatchDataLog {
    prefix_len: usize,
    suffix: Mutex<MatchDataSuffix>,
    published: OnceLock<Vec<MatchedData>>,
}

#[derive(Default)]
struct MatchDataSuffix {
    owned: Vec<MatchedData>,
    /// Prepared records interleave with owned ones. The index is the number
    /// of owned records preceding this one.
    prepared: Vec<(usize, RuleAt)>,
}

impl RuleAt {
    fn prepared_data(self, ruleset: &CompiledRuleset) -> &MatchedData {
        ruleset.plans_for_phase(self.phase)[self.index]
            .shared_comparison
            .as_ref()
            .and_then(|comparison| comparison.record.as_ref())
            .expect("matched shared comparison")
    }
}

impl MatchDataLog {
    pub(super) fn restore(&mut self, prepared: &[MatchedData], last_is_open: bool) {
        self.prefix_len = prepared.len() - usize::from(last_is_open);
        self.published.take();
        let suffix = self.suffix.get_mut().unwrap();
        suffix.prepared.clear();
        suffix.owned.clear();
        suffix.owned.extend_from_slice(&prepared[self.prefix_len..]);
    }

    pub(super) fn records_mut(&mut self) -> &mut Vec<MatchedData> {
        match self.published.get_mut() {
            Some(records) => records,
            None => &mut self.suffix.get_mut().unwrap().owned,
        }
    }

    pub(super) fn push_prepared(&mut self, at: RuleAt, ruleset: &CompiledRuleset) {
        if let Some(records) = self.published.get_mut() {
            records.push(at.prepared_data(ruleset).clone());
        } else {
            let suffix = self.suffix.get_mut().unwrap();
            suffix.prepared.push((suffix.owned.len(), at));
        }
    }

    pub(super) fn as_slice(&self, ruleset: &CompiledRuleset) -> &[MatchedData] {
        self.published.get_or_init(|| {
            // Readers share &Transaction. Only the first one takes ownership of
            // the suffix, and subsequent phases append to the published vector.
            let suffix = std::mem::take(&mut *self.suffix.lock().unwrap());
            if self.prefix_len == 0 && suffix.prepared.is_empty() {
                return suffix.owned;
            }
            let mut records =
                Vec::with_capacity(self.prefix_len + suffix.owned.len() + suffix.prepared.len());
            if self.prefix_len != 0 {
                let initial = ruleset.initial_state().expect("prepared match data");
                records.extend_from_slice(&initial.matched_data[..self.prefix_len]);
            }
            let mut owned = suffix.owned.into_iter();
            let mut consumed = 0;
            for (before, at) in suffix.prepared {
                records.extend(owned.by_ref().take(before - consumed));
                records.push(at.prepared_data(ruleset).clone());
                consumed = before;
            }
            records.extend(owned);
            records
        })
    }
}
