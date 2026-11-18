
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct OracleRequestCollections(super::target_indices::RequestCollections,super::target_indices::RequestCollections);
#[cfg(test)]
impl CompiledRuleset {
    pub(crate) fn oracle_request_collections(&self,phase:Phase,input:&[u8])->OracleRequestCollections {
        use crate::variables::{ByteValue,RequestData};
        use super::target_indices::RequestCollections;
        let mut request=RequestData::new();
        request.args_get.add_bytes(input,input);
        request.args_post.add_bytes(input,input);
        request.binary_path=Some(ByteValue::from(input));
        let keys=&self.header_slots[phase.index()];
        for key in keys {request.headers.add_bytes(key.as_ref(),input);}
        let none=RequestCollections::new(&request,Default::default());
        let selected=RequestCollections::new(&request,self.width_sources[phase.index()]).with_headers(&request,keys);
        OracleRequestCollections(none,selected)
    }
    pub(crate) fn oracle_phase_pruned(&self,phase:Phase,index:usize,req:OracleRequestCollections)->[usize;3] {
        use crate::parser::VariableName;
        let vars=&self.rules_for_phase(phase)[index].variables;
        let targets=&self.dispatch_for_phase(phase)[index].targets;
        let available=targets.select(req.1).indices(vars).fold(0u16,|m,i|m|1u16.checked_shl(i as u32).unwrap_or(0));
        let mut counts=[0;3];
        for i in targets.select(req.0).indices(vars) {
            if i>=16 || available & (1<<i)!=0 {continue;}
            assert!(!vars[i].count_mode);
            let n=match vars[i].name{
                VariableName::RequestFilename=>1,
                VariableName::RequestHeaders=>2,
                VariableName::Args|VariableName::ArgsNames|VariableName::ArgsGet|VariableName::ArgsGetNames|VariableName::ArgsPost|VariableName::ArgsPostNames=>0,
                other=>panic!("unexpected pruned target {other:?}"),
            };
            counts[n]+=1;
        }
        counts
    }
}
