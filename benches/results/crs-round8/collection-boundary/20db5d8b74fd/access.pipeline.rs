
#[cfg(test)]
impl TransformationPipeline {
    pub(crate) fn oracle_without_shortcuts(&self)->Self {
        let mut p=self.clone();
        p.byte_triggers=None;
        p
    }
}
