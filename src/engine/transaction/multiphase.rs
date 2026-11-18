//! Match history for chains scheduled in more than one Coraza phase.

use std::collections::{HashMap, HashSet};

use crate::parser::VariableName;
use crate::variables::ByteValue;

// Coraza compares the variable collection and transformed value, ignoring
// the member key. A completed chain represents all combinations of its links.
type Link = HashSet<(Option<VariableName>, ByteValue)>;
type Chain = Vec<Link>;

#[derive(Default)]
pub(super) struct ChainHistory {
    completed: HashMap<String, Vec<Chain>>,
    pending: Chain,
}

impl ChainHistory {
    pub(super) fn accept(
        &mut self,
        id: &str,
        depth: usize,
        first: bool,
        last: bool,
        field: (Option<VariableName>, ByteValue),
    ) -> bool {
        if first {
            self.pending.truncate(depth);
            self.pending.push(Link::new());
        }
        if last && field.0.is_some() {
            // Two Cartesian products overlap exactly when every pair of
            // corresponding levels overlaps. Test that without expanding
            // the products, which can grow exponentially with chain length.
            if self.completed.get(id).is_some_and(|histories| {
                histories.iter().any(|old| {
                    old.len() == depth + 1
                        && old[depth].contains(&field)
                        && old[..depth]
                            .iter()
                            .zip(&self.pending)
                            .all(|(left, right)| !left.is_disjoint(right))
                })
            }) {
                return false;
            }
        }
        self.pending[depth].insert(field);
        true
    }

    pub(super) fn complete(&mut self, id: &str) {
        let chain = std::mem::take(&mut self.pending);
        if let Some(histories) = self.completed.get_mut(id) {
            histories.push(chain);
        } else {
            self.completed.insert(id.to_owned(), vec![chain]);
        }
    }
}
