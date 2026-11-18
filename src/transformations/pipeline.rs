//! Transformation pipeline.

use super::{create_transformation, Transformation};
use crate::error::Result;
use std::borrow::Cow;
use std::sync::Arc;

// For built-in normalization pipelines, these flags mark bytes that may
// change at least one stage. A byte outside every stage's trigger set is
// copied verbatim by each of them, so even multiMatch has no stage to visit.
const NON_ASCII: u16 = 1;
const UPPER: u16 = 1 << 1;
const SPACE: u16 = 1 << 2;
const URL: u16 = 1 << 3;
const ENTITY: u16 = 1 << 4;
const BACKSLASH: u16 = 1 << 5;
const NUL: u16 = 1 << 6;
const SLASH: u16 = 1 << 7;
const COMMENT: u16 = 1 << 8;
const SHELL: u16 = 1 << 9;
const PATH: u16 = 1 << 10;

const BYTE_FLAGS: [u16; 256] = {
    let mut flags = [0; 256];
    let mut i = 0;
    while i < flags.len() {
        let b = i as u8;
        flags[i] = match b {
            0 => NUL,
            b'%' | b'+' => URL,
            b'&' => ENTITY,
            b'\\' => BACKSLASH,
            b'/' => SLASH,
            b'-' | b'#' => COMMENT,
            b'"' | b'\'' | b'^' | b',' | b';' => SHELL,
            b'A'..=b'Z' => UPPER,
            b' ' | b'\t'..=b'\r' => SPACE,
            0x80..=0xff => NON_ASCII,
            _ => 0,
        };
        i += 1;
    }
    flags
};

// On ASCII path tokens, every listed stage except PATH preserves the alphabet
// and cannot increase the byte count. This also holds for alphanumeric input.
fn byte_triggers(name: &str) -> Option<u16> {
    match name {
        "utf8ToUnicode" => Some(NON_ASCII),
        "urlDecode" | "urlDecodeUni" => Some(URL),
        "htmlEntityDecode" => Some(ENTITY),
        "jsDecode" | "cssDecode" | "escapeSeqDecode" => Some(BACKSLASH),
        "removeNulls" | "replaceNulls" => Some(NUL),
        "lowercase" => Some(NON_ASCII | UPPER),
        "removeWhitespace" | "compressWhitespace" => Some(NON_ASCII | SPACE),
        "normalizePath" => Some(PATH | SLASH),
        "normalizePathWin" => Some(PATH | SLASH | BACKSLASH),
        "replaceComments" | "removeComments" => Some(SLASH),
        "removeCommentsChar" => Some(SLASH | COMMENT),
        "cmdLine" => Some(NON_ASCII | UPPER | BACKSLASH | SPACE | SHELL),
        _ => None,
    }
}

/// A pipeline of transformations to apply in sequence.
#[derive(Clone)]
pub struct TransformationPipeline {
    transformations: Vec<Arc<dyn Transformation>>,
    byte_triggers: Option<u16>,
}

impl TransformationPipeline {
    /// Create an empty pipeline.
    pub fn new() -> Self {
        Self {
            transformations: Vec::new(),
            byte_triggers: None,
        }
    }

    /// Create a pipeline from transformation names.
    pub fn from_names(names: &[String]) -> Result<Self> {
        let mut transformations = Vec::new();
        let mut triggers = Some(0);

        for name in names {
            // Handle "none" specially - it clears the pipeline
            if name.eq_ignore_ascii_case("none") {
                transformations.clear();
                triggers = Some(0);
                continue;
            }

            let t = create_transformation(name)?;
            triggers = triggers
                .zip(byte_triggers(t.name()))
                .map(|(combined, stage)| combined | stage);
            transformations.push(t);
        }

        Ok(Self {
            byte_triggers: triggers.filter(|_| !transformations.is_empty()),
            transformations,
        })
    }

    /// Add a transformation to the pipeline.
    pub fn add(&mut self, transformation: Arc<dyn Transformation>) {
        // A custom stage may use any name and can have arbitrary behavior.
        self.byte_triggers = None;
        self.transformations.push(transformation);
    }

    /// Apply all transformations in sequence.
    pub fn apply<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if self.transformations.is_empty() {
            return Cow::Borrowed(input);
        }

        let mut current: Cow<str> = Cow::Borrowed(input);

        for t in &self.transformations {
            current = match current {
                Cow::Borrowed(s) => t.transform(s),
                Cow::Owned(s) => {
                    let transformed = t.transform(&s);
                    match transformed {
                        Cow::Borrowed(next)
                            if next.as_ptr() == s.as_ptr() && next.len() == s.len() =>
                        {
                            Cow::Owned(s)
                        }
                        Cow::Borrowed(next) => Cow::Owned(next.to_owned()),
                        Cow::Owned(new) => Cow::Owned(new),
                    }
                }
            };
        }

        current
    }

    /// Apply each transformation without converting binary values into text.
    #[inline]
    pub fn apply_bytes<'a>(&self, input: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        if self.input_is_unchanged(input) {
            return Ok(Cow::Borrowed(input));
        }
        self.apply_byte_stages(input)
    }

    fn apply_byte_stages<'a>(&self, input: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        if let [only] = self.transformations.as_slice() {
            return only.transform_bytes(input);
        }
        let mut current = Cow::Borrowed(input);
        for transformation in &self.transformations {
            current = match current {
                Cow::Borrowed(value) => transformation.transform_bytes(value)?,
                Cow::Owned(value) => match transformation.transform_bytes(&value)? {
                    Cow::Borrowed(next)
                        if next.as_ptr() == value.as_ptr() && next.len() == value.len() =>
                    {
                        Cow::Owned(value)
                    }
                    Cow::Borrowed(next) => Cow::Owned(next.to_vec()),
                    Cow::Owned(next) => Cow::Owned(next),
                },
            };
        }
        Ok(current)
    }

    /// Visit the original value and every stage whose output changes it.
    ///
    /// `multiMatch` evaluates each of these values, including a match that a
    /// later transformation removes. Unchanged stages are not duplicate
    /// evaluations; revisiting a previous value after a real change is.
    pub fn for_each_stage(&self, input: &str, mut visit: impl FnMut(&str)) {
        let mut current: Cow<'_, str> = Cow::Borrowed(input);
        visit(&current);
        for transformation in &self.transformations {
            let next = transformation.transform(&current);
            if next.as_ref() != current.as_ref() {
                visit(&next);
                current = Cow::Owned(next.into_owned());
            }
        }
    }

    /// Visit original bytes and each changed stage for `multiMatch`.
    pub fn for_each_byte_stage(
        &self,
        input: &[u8],
        mut visit: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.visit_byte_stages(input, None, |_, value| {
            visit(value)?;
            Ok(None::<()>)
        })?;
        Ok(())
    }

    /// Stop at a changed stage and resume after it without repeating the
    /// transformation or operator. Stage zero denotes the original value.
    pub(crate) fn visit_byte_stages<B>(
        &self,
        input: &[u8],
        after: Option<usize>,
        mut visit: impl FnMut(usize, &[u8]) -> Result<Option<B>>,
    ) -> Result<Option<B>> {
        if after.is_none() {
            if let Some(done) = visit(0, input)? {
                return Ok(Some(done));
            }
        }
        if self.input_is_unchanged(input) {
            return Ok(None);
        }
        let mut current: Cow<'_, [u8]> = Cow::Borrowed(input);
        for (index, transformation) in self
            .transformations
            .iter()
            .enumerate()
            .skip(after.unwrap_or(0))
        {
            let next = transformation.transform_bytes(&current)?;
            if next.as_ref() != current.as_ref() {
                if let Some(done) = visit(index + 1, &next)? {
                    return Ok(Some(done));
                }
                current = Cow::Owned(next.into_owned());
            }
        }
        Ok(None)
    }

    #[inline]
    fn input_is_unchanged(&self, input: &[u8]) -> bool {
        // Above a short header or argument, the stages' vectorized searches
        // are faster than scanning a byte classification table.
        self.transformations.is_empty()
            || input.len() <= 64
                && self.byte_triggers.is_some_and(|flags| {
                    // With no separator, only these complete path components change.
                    !(flags & PATH != 0 && matches!(input, b"." | b".."))
                        && input
                            .iter()
                            .all(|&byte| BYTE_FLAGS[usize::from(byte)] & flags == 0)
                })
    }

    // These stages also preserve dotted words: without a separator, path cleaning
    // can only shorten a standalone dot component.
    pub(crate) fn preserves_alphanumeric_width_bounds(&self) -> bool {
        self.is_empty() || self.byte_triggers.is_some()
    }

    // Case folding and removing comment markers can change individual bytes,
    // while preserving both alphabets used by the regex minimum-width check.
    // Path normalization can turn a single slash into two.
    pub(crate) fn preserves_token_width_bounds(&self) -> bool {
        self.is_empty() || self.byte_triggers.is_some_and(|flags| flags & PATH == 0)
    }

    /// Check if the pipeline is empty.
    pub fn is_empty(&self) -> bool {
        self.transformations.is_empty()
    }

    /// Get the number of transformations.
    pub fn len(&self) -> usize {
        self.transformations.len()
    }
}

impl Default for TransformationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TransformationPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransformationPipeline")
            .field(
                "transformations",
                &self
                    .transformations
                    .iter()
                    .map(|t| t.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_pipeline() {
        let pipeline = TransformationPipeline::new();
        assert_eq!(pipeline.apply("hello"), "hello");
    }

    #[test]
    fn test_single_transformation() {
        let pipeline = TransformationPipeline::from_names(&["lowercase".to_string()]).unwrap();
        assert_eq!(pipeline.apply("HELLO"), "hello");
    }

    #[test]
    fn test_multiple_transformations() {
        let pipeline =
            TransformationPipeline::from_names(&["urlDecode".to_string(), "lowercase".to_string()])
                .unwrap();
        assert_eq!(pipeline.apply("HELLO%20WORLD"), "hello world");
    }

    #[test]
    fn only_token_preserving_pipelines_can_skip_a_regex_search() {
        for (name, preserves) in [
            ("urlDecode", true),
            ("removeNulls", true),
            ("lowercase", true),
            ("removeCommentsChar", true),
            ("replaceComments", true),
            ("normalizePath", false),
            ("cmdLine", true),
            ("base64Encode", false),
        ] {
            let pipeline = TransformationPipeline::from_names(&[name.into()]).unwrap();
            assert_eq!(pipeline.preserves_token_width_bounds(), preserves, "{name}");
        }
    }

    #[test]
    fn compiled_shortcuts_preserve_output_and_changed_stages() {
        let mut inputs: Vec<Vec<u8>> = (0..=255).map(|byte| vec![b'a', byte, b'b']).collect();
        inputs.extend([
            b"catalog".to_vec(),
            b"%26amp%3B".to_vec(),
            br"a\x42".to_vec(),
            b"ab\x00cd".to_vec(),
            b"a/../b".to_vec(),
            b".".to_vec(),
            b"..".to_vec(),
            b"json.items_0.name".to_vec(),
            b"one  two".to_vec(),
            "Straße Σ".as_bytes().to_vec(),
            b"a\xffZ".to_vec(),
            vec![b'a'; 65],
        ]);
        for names in [
            "urlDecodeUni",
            "cmdLine",
            "lowercase",
            "normalizePath",
            "replaceComments",
            "compressWhitespace",
            "utf8ToUnicode urlDecodeUni htmlEntityDecode jsDecode cssDecode removeNulls",
            "urlDecode removeWhitespace",
            "urlDecodeUni lowercase",
            "cmdLine normalizePath",
            "normalizePathWin escapeSeqDecode",
            "replaceComments removeCommentsChar",
            "compressWhitespace removeNulls",
            "hexDecode none urlDecode jsDecode",
        ] {
            let names: Vec<String> = names.split_whitespace().map(str::to_owned).collect();
            let compiled = TransformationPipeline::from_names(&names).unwrap();
            let mut individual = TransformationPipeline::new();
            for name in names {
                if name == "none" {
                    individual = TransformationPipeline::new();
                } else {
                    individual.add(create_transformation(&name).unwrap());
                }
            }
            for input in &inputs {
                let expected = individual.apply_bytes(input).unwrap();
                let actual = compiled.apply_bytes(input).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(
                    matches!(actual, Cow::Borrowed(_)),
                    matches!(expected, Cow::Borrowed(_))
                );
                for after in [None, Some(1)] {
                    let stages = |pipeline: &TransformationPipeline| {
                        let mut rows = Vec::new();
                        pipeline
                            .visit_byte_stages(input, after, |index, value| {
                                rows.push((index, value.to_vec()));
                                Ok(None::<()>)
                            })
                            .unwrap();
                        rows
                    };
                    assert_eq!(stages(&compiled), stages(&individual));
                }
            }
        }
    }

    #[test]
    fn a_custom_stage_is_executed_even_when_its_name_matches_a_builtin() {
        struct Custom;
        impl Transformation for Custom {
            fn name(&self) -> &'static str {
                "urlDecode"
            }
            fn transform<'a>(&self, _: &'a str) -> Cow<'a, str> {
                Cow::Borrowed("custom")
            }
        }
        let mut pipeline =
            TransformationPipeline::from_names(&["urlDecode".into(), "jsDecode".into()]).unwrap();
        assert!(matches!(
            pipeline.apply_bytes(b"catalog").unwrap(),
            Cow::Borrowed(_)
        ));
        pipeline.add(Arc::new(Custom));
        assert_eq!(
            pipeline.apply_bytes(b"catalog").unwrap().as_ref(),
            b"custom"
        );
    }

    #[test]
    fn test_none_clears_pipeline() {
        let pipeline = TransformationPipeline::from_names(&[
            "lowercase".to_string(),
            "none".to_string(),
            "uppercase".to_string(),
        ])
        .unwrap();
        // Only uppercase should be applied
        assert_eq!(pipeline.apply("hello"), "HELLO");
    }
}
