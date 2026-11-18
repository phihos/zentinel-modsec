use zentinel_modsec::{Error, ModSecurity};
fn main() {
    for (kind, phase) in [("request",1),("response",3)] {
        for action in ["Reject","ProcessPartial"] {
            for limit in [0,4,12] {
                let rules = format!("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\nSecRequestBodyLimit 8\nSecResponseBodyLimit 8\nSecRequestBodyLimitAction {action}\nSecResponseBodyLimitAction {action}\nSecAction \"id:1,phase:{phase},pass,nolog,ctl:{kind}BodyLimit={limit}\"\nSecRule INBOUND_DATA_ERROR \"@streq 1\" \"id:2,phase:2,pass,log\"\nSecRule OUTBOUND_DATA_ERROR \"@streq 1\" \"id:3,phase:4,pass,log\"");
                let engine=ModSecurity::from_string(&rules).unwrap();
                for chunk in ["ab","abcd","abcdefghi","abcdefghijkl"] {
                    let mut t=engine.new_transaction();
                    t.process_uri("/","POST","HTTP/1.1").unwrap();
                    t.process_request_headers().unwrap();
                    let written=if kind=="response" {
                        t.process_request_body().unwrap();
                        t.add_response_header("Content-Type","text/plain").unwrap();
                        t.process_response_headers_with_status(200,"HTTP/1.1").unwrap();
                        let result=t.write_response_body(chunk.as_bytes());t.process_response_body().unwrap(); result
                    } else {
                        let result=t.write_request_body(chunk.as_bytes());t.process_request_body().unwrap();result
                    };
                    let (n,error)=match written {Ok(w)=>(w.consumed,"<nil>"),Err(Error::BodyStorageLimit{..})=>(0,"limit reached while writing"),Err(e)=>panic!("{e}")};
                    let flags=t.matched_rules().iter().filter(|id|id.as_str()!="1").map(String::as_str).collect::<Vec<_>>().join(" ");
                    println!("{kind} {action} {limit} {} consumed {n} status {} error {error} flagmatch [{flags}]",chunk.len(),t.intervention().map_or(0,|i|i.status));
                }
            }
        }
    }
}
