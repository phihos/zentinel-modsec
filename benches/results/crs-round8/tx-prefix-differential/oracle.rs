use regex::bytes::RegexBuilder;
use zentinel_modsec::{parser::{VariableSpec,Selection,VariableName}, variables::{ByteCollection, RequestData, ResponseData, TxCollection, VariableResolver}};

fn main() {
    let request = RequestData::default(); let response = ResponseData::default(); let mut tx = TxCollection::default();
    for prefix in ["","a","s","k","S","K","ſ","K","Ä","İ","header_name_920450_", "header_name_920451_"] {
        for b in 0..=255u8 {
            for suffix in [b"".as_slice(), b"_c", b"_\xfe", b"Header_Name_920450_"] {
                let mut key=prefix.as_bytes().to_vec(); key.push(b); key.extend_from_slice(suffix);
                tx.set_bytes(key.clone(),key);
            }
        }
    }
    tx.set_bytes(&b""[..],"empty"); tx.set_bytes(r"\xff","text");
    for k in ["s", "ſ","K", "k","1","_","HEADER_NAME_920450_"] {tx.set_bytes(k,k);}
    let resolver=VariableResolver::new(&request,&response,&tx,None,&[],&[]);
    let patterns=["^s", "^k", "^1", "^_", "^a", "^a_", "^header_name_920450_", "^header_name_920451_", "^header_name_92045", "^ſ", "^K", "^A", "^S", "^a.b","^a|s","^a$","(?m)^a", "(?-i)^a","(?i)^s","a","^","^[s]","^k.*","^s[0-9]", "^header-n","^zzzz"];
    for p in patterns {
        let spec=VariableSpec{name:VariableName::Tx,selection:Some(Selection::Regex(p.into())),count_mode:false,exclusions:vec![]};
        let re=RegexBuilder::new(p).case_insensitive(true).build().unwrap();
        let expected=tx.get_regex_bytes(&re);
        let actual=resolver.resolve_bytes(&spec);
        assert_eq!(expected.len(),actual.len(),"{p}");
        for ((key,val),(name,value)) in expected.iter().zip(&actual) {
            let expected_name=if key.is_empty() { b"TX".to_vec() } else {[b"TX:".as_slice(), *key].concat()};
            assert_eq!(name.as_bytes(),expected_name,"{p}"); assert_eq!(value.as_bytes(),*val,"{p}");
        }
    }
    println!("{} folded and opaque keys x {} regex selectors; all exact against regex::bytes", tx.all_bytes().len(), patterns.len());
}
