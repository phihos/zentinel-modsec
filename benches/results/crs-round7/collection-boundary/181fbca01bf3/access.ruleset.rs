
#[cfg(test)]
impl CompiledRuleset {
    // Keep present collections, exact header slots and optional member signatures
    // identical. Toggle only the optimization under test.
    pub(crate) fn oracle_args_removed(&self, phase:Phase, index:usize, request:&crate::variables::RequestData)->Vec<usize> {
        use super::target_indices::RequestCollections;
        let source=self.width_sources[phase.index()];
        let mut without=source;
        without.arguments=false;
        let snapshot=|source|RequestCollections::new(request,source).with_headers(request,&self.header_slots[phase.index()]);
        let vars=&self.rules_for_phase(phase)[index].variables;
        let targets=&self.dispatch_for_phase(phase)[index].targets;
        let selected=targets.select(snapshot(source)).indices(vars).collect::<Vec<_>>();
        targets.select(snapshot(without)).indices(vars).filter(|i| !selected.contains(i)).collect()
    }
    pub(crate) fn disable_argument_widths_for_oracle(&mut self) {
        for sources in &mut self.width_sources {sources.arguments=false;}
    }
}
