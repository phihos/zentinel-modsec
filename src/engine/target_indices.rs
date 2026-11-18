//! Compile short rule target lists for each combination of phase-stable collections.
use crate::parser::{VariableName, VariableSpec};
use crate::variables::RequestData;

const GET: u8 = 1;
const POST: u8 = 2;
const COOKIES: u8 = 4;
const XML: u8 = 8;
pub(super) const HEADER_SLOTS: usize = 2;
pub(super) const PREFIX: usize = u16::BITS as usize;

const FILES: u64 = 1 << 63;
const FILE_NAMES: u64 = 1 << 62;
const PART_HEADERS: u64 = 1 << 61;
const HEADER_BITS: u64 = PART_HEADERS - 1;

// Collisions retain an ordinary indexed lookup. Only disjoint bit sets prove absence.
fn header_bit(key: &[u8]) -> u64 {
    let first = usize::from(key.first().copied().unwrap_or(0));
    let last = usize::from(key.last().copied().unwrap_or(0));
    1 << (first * 17 + last + key.len()) % 61
}

// Maximum length for each alphabet. A non-member or a long input disables
// that bound for the whole group so every original candidate remains visible.
#[derive(Clone, Copy, Default)]
struct Widths {
    word: u8,
    path: u8,
}

impl Widths {
    const UNKNOWN: Self = Self {
        word: u8::MAX,
        path: u8::MAX,
    };

    fn include(&mut self, input: &[u8]) {
        if input.len() > 64 {
            *self = Self::UNKNOWN;
        } else if self.path != u8::MAX {
            let len = input.len() as u8;
            if self.word != u8::MAX && input.iter().all(u8::is_ascii_alphanumeric) {
                self.word = self.word.max(len);
                self.path = self.path.max(len);
            } else if input.iter().copied().all(crate::operators::token_byte) {
                self.word = u8::MAX;
                self.path = self.path.max(len);
            } else {
                *self = Self::UNKNOWN;
            }
        }
    }

    fn below(self, minimum: [u8; 2]) -> bool {
        self.word < minimum[0] || self.path < minimum[1]
    }
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub(super) struct WidthSources {
    pub arguments: bool,
    pub filename: bool,
    pub optional_targets: bool,
}

#[derive(Clone, Copy)]
pub(super) struct RequestCollections {
    present: u8,
    optional: u64,
    widths: [Widths; 3],
    headers: [Option<Widths>; HEADER_SLOTS],
}

impl RequestCollections {
    pub fn new(request: &RequestData, sources: WidthSources) -> Self {
        let present = (u8::from(!request.args_get.is_empty()) * GET)
            | (u8::from(!request.args_post.is_empty()) * POST)
            | (u8::from(!request.cookies.is_empty()) * COOKIES)
            | (u8::from(!request.xml.is_empty()) * XML);
        let mut widths = [Widths::UNKNOWN; 3];
        if sources.filename {
            widths[2] = Widths::default();
            widths[2].include(request.path_bytes());
        }
        if sources.arguments && present & (GET | POST) != 0 {
            widths[..2].fill(Widths::default());
            let mut remaining = 32;
            let mut visit = |name: &[u8], value: &[u8]| {
                widths[0].include(value);
                widths[1].include(name);
            };
            if !request.args_get.visit_bounded(&mut remaining, &mut visit)
                || !request.args_post.visit_bounded(&mut remaining, visit)
            {
                widths[..2].fill(Widths::UNKNOWN);
            }
        }
        let mut optional = u64::MAX;
        if sources.optional_targets {
            let keys = request.headers.canonical_keys();
            let headers = if keys.len() <= 32 {
                keys.fold(0, |mask, key| mask | header_bit(key))
            } else {
                HEADER_BITS
            };
            optional = headers
                | (u64::from(!request.files.is_empty()) * FILES)
                | (u64::from(!request.files_names.is_empty()) * FILE_NAMES)
                | (u64::from(!request.multipart_part_headers.is_empty()) * PART_HEADERS);
        }
        Self {
            present,
            optional,
            widths,
            headers: [Some(Widths::UNKNOWN); HEADER_SLOTS],
        }
    }

    pub fn with_headers(mut self, request: &RequestData, keys: &[Box<[u8]>]) -> Self {
        for (slot, key) in self.headers.iter_mut().zip(keys) {
            *slot = request.headers.canonical_values(key).map(|values| {
                let mut widths = Widths::default();
                if values.len() > 32 {
                    return Widths::UNKNOWN;
                }
                for value in values {
                    widths.include(value.as_bytes());
                }
                widths
            });
        }
        self
    }

    fn includes(present: u8, spec: &VariableSpec) -> bool {
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
        present & collections != 0
    }
}

#[derive(Default)]
pub(super) struct TargetIndices {
    present: [u16; 16],
    bounded_targets: [u16; 3],
    optional_targets: u16,
    optional_keys: u64,
    pub(super) header_targets: [u16; HEADER_SLOTS],
    minimum: [u8; 2],
}

impl TargetIndices {
    pub fn compile(targets: &[VariableSpec], minimum: [u8; 2]) -> Self {
        let mut masks = Self {
            minimum,
            ..Self::default()
        };
        for (index, spec) in targets.iter().take(PREFIX).enumerate() {
            if minimum != [0; 2] && !spec.count_mode {
                use VariableName::*;
                match spec.name {
                    Args | ArgsGet | ArgsPost => masks.bounded_targets[0] |= 1 << index,
                    ArgsNames | ArgsGetNames | ArgsPostNames => {
                        masks.bounded_targets[1] |= 1 << index
                    }
                    RequestFilename => masks.bounded_targets[2] |= 1 << index,
                    _ => {}
                }
            }
            if !spec.count_mode {
                let key = match spec.name {
                    VariableName::Files => FILES,
                    VariableName::FilesNames => FILE_NAMES,
                    VariableName::MultipartPartHeaders => PART_HEADERS,
                    _ => 0,
                };
                if key != 0 {
                    masks.optional_targets |= 1 << index;
                    masks.optional_keys |= key;
                }
            }
            for (available, mask) in masks.present.iter_mut().enumerate() {
                if RequestCollections::includes(available as u8, spec) {
                    *mask |= 1 << index;
                }
            }
        }
        masks
    }

    pub fn add_optional_header(&mut self, index: usize, key: &[u8]) {
        self.optional_keys |= header_bit(key);
        self.optional_targets |= 1 << index;
    }

    pub fn add_width_sources(&self, sources: &mut WidthSources) {
        sources.arguments |= self.bounded_targets[0] != 0 || self.bounded_targets[1] != 0;
        sources.filename |= self.bounded_targets[2] != 0;
        sources.optional_targets |= self.optional_targets != 0;
    }

    #[inline]
    fn selected(&self, available: RequestCollections) -> u16 {
        let mut mask = self.present[usize::from(available.present)];
        if available.optional & self.optional_keys == 0 {
            mask &= !self.optional_targets;
        }
        if available.widths[0].below(self.minimum) {
            mask &= !self.bounded_targets[0];
        }
        if available.widths[1].below(self.minimum) {
            mask &= !self.bounded_targets[1];
        }
        if available.widths[2].below(self.minimum) {
            mask &= !self.bounded_targets[2];
        }
        for (targets, widths) in self.header_targets.iter().zip(available.headers) {
            if widths.is_none_or(|width| width.below(self.minimum)) {
                mask &= !targets;
            }
        }
        mask
    }

    pub fn select(&self, available: RequestCollections) -> ActiveTargets {
        ActiveTargets {
            bits: self.selected(available),
            collections: available.present,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct ActiveTargets {
    bits: u16,
    collections: u8,
}

impl ActiveTargets {
    /// A SecAction has no target. Targets beyond the precompiled prefix are
    /// resolved individually in the same order as the original list.
    pub fn may_match(self, count: usize) -> bool {
        count == 0 || count > PREFIX || self.bits != 0
    }
    pub fn indices(self, targets: &[VariableSpec]) -> impl Iterator<Item = usize> + '_ {
        let mut bits = self.bits;
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
            (PREFIX..targets.len()).filter(move |&index| {
                RequestCollections::includes(self.collections, &targets[index])
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_snapshot(present: u8) -> RequestCollections {
        RequestCollections {
            present,
            optional: u64::MAX,
            widths: [Widths::UNKNOWN; 3],
            headers: [Some(Widths::UNKNOWN); HEADER_SLOTS],
        }
    }

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
                TargetIndices::compile(&targets, [0; 2])
                    .select(empty_snapshot(state),)
                    .may_match(targets.len()),
                may_match
            );
        }
        let mut targets = vec![crate::parser::parse_single_variable("ARGS").unwrap(); PREFIX];
        targets.push(crate::parser::parse_single_variable("REQUEST_URI").unwrap());
        assert!(TargetIndices::compile(&targets, [0; 2])
            .select(empty_snapshot(0),)
            .may_match(targets.len()));
    }

    #[test]
    fn prune_values_and_observed_names_independently_and_keep_counts() {
        let mut request = RequestData::default();
        request.args_get.add_bytes("q", "abc");
        request.args_post.add_bytes("Name.Dotted", "1234");
        let targets: Vec<_> = ["ARGS", "ARGS_NAMES", "&ARGS", "TX:late", "ARGS_POST:Name"]
            .map(|name| crate::parser::parse_single_variable(name).unwrap())
            .into();
        let active = |minimum| {
            TargetIndices::compile(&targets, minimum)
                .select(RequestCollections::new(
                    &request,
                    WidthSources {
                        arguments: true,
                        filename: false,
                        optional_targets: false,
                    },
                ))
                .indices(&targets)
                .collect::<Vec<_>>()
        };
        assert_eq!(active([5, 0]), [1, 2, 3]);
        assert_eq!(active([5, 12]), [2, 3]);
        assert_eq!(active([4, 0]), [0, 1, 2, 3, 4]);
    }

    #[test]
    fn argument_budget_is_shared_across_duplicate_query_and_body_members() {
        let mut request = RequestData::default();
        let target = crate::parser::parse_single_variable("ARGS").unwrap();
        let plan = TargetIndices::compile(&[target], [65, 65]);
        for _ in 0..31 {
            request.args_get.add_bytes("same", "tiny");
        }
        request.args_post.add_bytes("same", "body");
        assert!(!plan
            .select(RequestCollections::new(
                &request,
                WidthSources {
                    arguments: true,
                    filename: false,
                    optional_targets: false
                }
            ))
            .may_match(1));
        request.args_post.add_bytes("same", "last");
        assert!(plan
            .select(RequestCollections::new(
                &request,
                WidthSources {
                    arguments: true,
                    filename: false,
                    optional_targets: false
                }
            ))
            .may_match(1));
    }

    #[test]
    fn selected_prefix_and_uncompiled_tail_keep_original_order() {
        let mut specs = vec![crate::parser::parse_single_variable("ARGS").unwrap(); PREFIX + 2];
        specs[3] = crate::parser::parse_single_variable("TX:late").unwrap();
        let plan = TargetIndices::compile(&specs, [65; 2]);
        let mut snapshot = empty_snapshot(GET);
        snapshot.widths[0] = Widths::default();
        let active = plan.select(snapshot);
        assert!(active.may_match(specs.len()));
        assert_eq!(
            active.indices(&specs).collect::<Vec<_>>(),
            [3, PREFIX, PREFIX + 1]
        );
    }

    #[test]
    fn optional_presence_only_prunes_when_all_named_sources_are_absent() {
        let specs = [
            "REQUEST_HEADERS:alpha",
            "FILES",
            "FILES_NAMES",
            "MULTIPART_PART_HEADERS",
            "&FILES",
        ]
        .map(|text| crate::parser::parse_single_variable(text).unwrap());
        let mut plan = TargetIndices::compile(&specs, [0; 2]);
        plan.add_optional_header(0, b"alpha");
        let active = |request: &RequestData| {
            let mut sources = WidthSources::default();
            plan.add_width_sources(&mut sources);
            plan.select(RequestCollections::new(request, sources))
                .indices(&specs)
                .collect::<Vec<_>>()
        };
        let mut request = RequestData::default();
        assert_eq!(active(&request), [4]);
        request.add_header("AmIdA", "collision");
        assert_eq!(header_bit(b"alpha"), header_bit(b"amida"));
        assert_eq!(active(&request), [0, 1, 2, 3, 4]);
        let mut request = RequestData::default();
        request.files_names.add_bytes("file", "upload");
        assert_eq!(active(&request), [0, 1, 2, 3, 4]);
        let mut request = RequestData::default();
        for n in 0..33 {
            request.add_header(&format!("x-{n}"), "v");
        }
        assert_eq!(active(&request), [0, 1, 2, 3, 4]);
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
        let plan = TargetIndices::compile(&targets, [0; 2]);
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
                plan.select(empty_snapshot(state),)
                    .indices(&targets)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
}
