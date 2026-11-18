
#[cfg(test)]
impl CompiledRuleset {
    pub(crate) fn oracle_phrase_pruned(&self,phase:Phase,index:usize,input:&[u8])->usize {
        use crate::variables::RequestData;
        use super::target_indices::RequestCollections;
        let mut request=RequestData::new();
        request.args_get.add_bytes(input,input);
        request.args_post.add_bytes(input,input);
        let vars=&self.rules_for_phase(phase)[index].variables;
        let targets=&self.dispatch_for_phase(phase)[index].targets;
        let ordinary=targets.active(RequestCollections::new(&request,false),vars).count();
        let filtered=targets.active(RequestCollections::new(&request,true),vars).count();
        ordinary.checked_sub(filtered).unwrap()
    }
}
