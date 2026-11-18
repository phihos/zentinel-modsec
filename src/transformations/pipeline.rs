//! Transformation pipeline.

use super::{create_transformation, Transformation};
use crate::error::Result;
use std::borrow::Cow;
use std::sync::Arc;

/// A pipeline of transformations to apply in sequence.
#[derive(Clone)]
pub struct TransformationPipeline {
    transformations: Vec<Arc<dyn Transformation>>,
}

impl TransformationPipeline {
    /// Create an empty pipeline.
    pub fn new() -> Self {
        Self {
            transformations: Vec::new(),
        }
    }

    /// Create a pipeline from transformation names.
    pub fn from_names(names: &[String]) -> Result<Self> {
        let mut transformations = Vec::new();

        for name in names {
            // Handle "none" specially - it clears the pipeline
            if name.eq_ignore_ascii_case("none") {
                transformations.clear();
                continue;
            }

            let t = create_transformation(name)?;
            transformations.push(t);
        }

        Ok(Self { transformations })
    }

    /// Add a transformation to the pipeline.
    pub fn add(&mut self, transformation: Arc<dyn Transformation>) {
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
    pub fn apply_bytes<'a>(&self, input: &'a [u8]) -> Result<Cow<'a, [u8]>> {
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
