//! Conservative match-width bounds over the original bytes of request fields.

// For a bounded group, remember its longest field and narrowest shared alphabet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Widths {
    longest: u8,
    alphabet: Alphabet,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Alphabet {
    #[default]
    Word,
    Dotted,
    Path,
}

impl Widths {
    pub(crate) const UNKNOWN: Self = Self {
        longest: u8::MAX,
        alphabet: Alphabet::Word,
    };

    pub(crate) fn include(&mut self, input: &[u8]) {
        if input.len() > 64 {
            *self = Self::UNKNOWN;
        } else if self.longest != u8::MAX {
            if self.alphabet != Alphabet::Word || !input.iter().all(u8::is_ascii_alphanumeric) {
                if self.alphabet != Alphabet::Path
                    && input
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || *b == b'.')
                {
                    self.alphabet = Alphabet::Dotted;
                } else if input.iter().copied().all(crate::operators::token_byte) {
                    self.alphabet = Alphabet::Path;
                } else {
                    *self = Self::UNKNOWN;
                    return;
                }
            }
            self.longest = self.longest.max(input.len() as u8);
        }
    }

    pub(crate) fn union(self, other: Self) -> Self {
        Self {
            longest: self.longest.max(other.longest),
            alphabet: self.alphabet.max(other.alphabet),
        }
    }

    pub(crate) fn below(self, minimum: [u8; 3]) -> bool {
        self.longest < minimum[self.alphabet as usize]
    }
}
