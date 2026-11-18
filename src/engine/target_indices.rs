//! Compile short rule target lists for each combination of phase-stable collections.
use crate::parser::{VariableName, VariableSpec};
use crate::variables::RequestData;

const GET: u8 = 1;
const POST: u8 = 2;
const COOKIES: u8 = 4;
const XML: u8 = 8;
const PREFIX: usize = u16::BITS as usize;

#[derive(Clone, Copy)]
pub(super) struct RequestCollections(u8);

impl RequestCollections {
    pub fn new(request: &RequestData) -> Self {
        let present = (u8::from(!request.args_get.is_empty()) * GET)
            | (u8::from(!request.args_post.is_empty()) * POST)
            | (u8::from(!request.cookies.is_empty()) * COOKIES)
            | (u8::from(!request.xml.is_empty()) * XML);
        Self(present)
    }

    fn includes(self, spec: &VariableSpec) -> bool {
        if spec.count_mode {
            return true;
        }
        use VariableName::*;
        let collections = match spec.name {
            Args | ArgsNames => GET | POST,
            ArgsGet | ArgsGetNames => GET,
            ArgsPost | ArgsPostNames => POST,
            RequestCookies | RequestCookiesNames => COOKIES,
            Xml => XML,
            _ => return true,
        };
        self.0 & collections != 0
    }
}

#[derive(Default)]
pub(super) struct TargetIndices([u16; 16]);

impl TargetIndices {
    pub fn compile(targets: &[VariableSpec]) -> Self {
        let mut masks = Self::default();
        for (index, spec) in targets.iter().take(PREFIX).enumerate() {
            for (available, mask) in masks.0.iter_mut().enumerate() {
                if RequestCollections(available as u8).includes(spec) {
                    *mask |= 1 << index;
                }
            }
        }
        masks
    }

    /// At least one target may resolve, or the rule has no target (SecAction).
    /// Only the first PREFIX targets have precompiled masks.
    pub fn may_match(&self, available: RequestCollections, count: usize) -> bool {
        count == 0 || count > PREFIX || self.0[usize::from(available.0)] != 0
    }

    pub fn active<'a>(
        &self,
        available: RequestCollections,
        targets: &'a [VariableSpec],
    ) -> impl Iterator<Item = usize> + 'a {
        let mut bits = self.0[usize::from(available.0)];
        let prefix = std::iter::from_fn(move || {
            if bits == 0 {
                return None;
            }
            let index = bits.trailing_zeros();
            bits &= bits - 1;
            Some(index as usize)
        });
        // Longer user-supplied lists have the same selection and ordering.
        prefix.chain(
            (PREFIX..targets.len()).filter(move |&index| available.includes(&targets[index])),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_skip_only_when_every_target_is_known_absent() {
        for (names, state, may_match) in [
            (vec![], 0, true),
            (vec!["ARGS", "XML"], 0, false),
            (vec!["ARGS", "XML"], GET, true),
            (vec!["ARGS", "XML"], POST, true),
            (vec!["&ARGS"], 0, true),
            (vec!["TX:late"], 0, true),
        ] {
            let targets: Vec<_> = names
                .iter()
                .map(|name| crate::parser::parse_single_variable(name).unwrap())
                .collect();
            assert_eq!(
                TargetIndices::compile(&targets)
                    .may_match(RequestCollections(state), targets.len()),
                may_match
            );
        }
        let mut targets = vec![crate::parser::parse_single_variable("ARGS").unwrap(); PREFIX];
        targets.push(crate::parser::parse_single_variable("REQUEST_URI").unwrap());
        assert!(TargetIndices::compile(&targets).may_match(RequestCollections(0), targets.len()));
    }

    #[test]
    fn long_lists_keep_order_counts_and_mutable_targets_for_all_collection_states() {
        let names = [
            "ARGS",
            "ARGS_NAMES",
            "ARGS_GET_NAMES",
            "ARGS_POST",
            "REQUEST_COOKIES_NAMES",
            "XML",
            "&ARGS",
            "TX:late",
            "REQUEST_URI",
        ];
        let targets: Vec<_> = names
            .iter()
            .cycle()
            .take(24)
            .map(|name| crate::parser::parse_single_variable(name).unwrap())
            .collect();
        let plan = TargetIndices::compile(&targets);
        for state in 0..16 {
            let expected: Vec<_> = (0..targets.len())
                .filter(|i| match i % names.len() {
                    0 | 1 => state & (GET | POST) != 0,
                    2 => state & GET != 0,
                    3 => state & POST != 0,
                    4 => state & COOKIES != 0,
                    5 => state & XML != 0,
                    _ => true,
                })
                .collect();
            assert_eq!(
                plan.active(RequestCollections(state), &targets)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
}
