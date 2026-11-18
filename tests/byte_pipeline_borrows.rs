use std::{borrow::Cow, sync::Arc};
use zentinel_modsec::transformations::{
    create_transformation, Transformation, TransformationPipeline,
};

struct Prefix;
impl Transformation for Prefix {
    fn transform<'a>(&self, value: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(&value[..1])
    }
    fn transform_bytes<'a>(&self, value: &'a [u8]) -> zentinel_modsec::Result<Cow<'a, [u8]>> {
        Ok(Cow::Borrowed(&value[..1]))
    }
    fn name(&self) -> &'static str {
        "customPrefix"
    }
}

#[test]
fn borrowed_subslices_after_owned_transforms_remain_the_next_value() {
    let mut pipeline = TransformationPipeline::new();
    pipeline.add(create_transformation("hexDecode").unwrap());
    pipeline.add(Arc::new(Prefix));
    assert_eq!(pipeline.apply_bytes(b"ff00").unwrap().as_ref(), b"\xff");
    let mut text = TransformationPipeline::new();
    text.add(create_transformation("lowercase").unwrap());
    text.add(Arc::new(Prefix));
    assert_eq!(text.apply("ABCD"), "a");
}
