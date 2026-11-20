//! Phase-local transformed bytes, shared only by identical built-in pipelines.
use std::borrow::Cow;

use crate::{error::Result, transformations::TransformationPipeline};

#[derive(Default)]
pub(super) struct TransformCache {
    slots: [Option<Entry>; 8],
}

struct Entry {
    group: usize,
    input: Box<[u8]>,
    output: Box<[u8]>,
}

impl TransformCache {
    pub(super) fn apply<'a>(
        &'a mut self,
        group: Option<usize>,
        pipeline: &TransformationPipeline,
        input: &'a [u8],
    ) -> Result<Cow<'a, [u8]>> {
        const MAX_BYTES: usize = 2048;
        if pipeline.input_is_unchanged(input) {
            return Ok(Cow::Borrowed(input));
        }
        let Some(group) = group.filter(|_| !input.is_empty() && input.len() <= MAX_BYTES) else {
            return pipeline.apply_byte_stages(input);
        };
        // A collision only replaces a slot. Compare all bytes, including
        // binary values and values from mutable TX members.
        let index = (group ^ input.len() ^ usize::from(input[0])) % self.slots.len();
        let slot = &mut self.slots[index];
        if !slot
            .as_ref()
            .is_some_and(|e| e.group == group && &*e.input == input)
        {
            match pipeline.apply_byte_stages(input)? {
                Cow::Owned(output) if output.len() <= MAX_BYTES => {
                    *slot = Some(Entry {
                        group,
                        input: input.into(),
                        output: output.into(),
                    });
                }
                other => return Ok(other),
            }
        }
        Ok(Cow::Borrowed(
            &slot.as_ref().expect("populated above").output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hits_use_full_binary_input_and_ordered_pipeline_identity() {
        let pipeline =
            |a: &str, b: &str| TransformationPipeline::from_names(&[a.into(), b.into()]).unwrap();
        let first = pipeline("urlDecode", "lowercase");
        let other = pipeline("lowercase", "urlDecode");
        let mut cache = TransformCache::default();
        for (group, stages, raw, expected) in [
            (0, &first, &b"%41\xff"[..], &b"a\xff"[..]),
            (0, &first, b"%41\xff", b"a\xff"),
            (0, &first, b"%42\xff", b"b\xff"),
            (8, &other, b"%42\xff", b"B\xff"),
        ] {
            assert_eq!(&*cache.apply(Some(group), stages, raw).unwrap(), expected);
        }
    }
}
