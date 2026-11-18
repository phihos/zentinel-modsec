use zentinel_modsec::{ModSecurity, Transaction, variables::ByteCollection};
use std::fmt::Write;
use std::sync::{Arc, Barrier};
struct Request {
    kind: usize,
    uri: String,
    method: &'static str,
    headers: Vec<(String,String)>,
    body: String,
}

fn requests() -> Vec<Request> {
    let mut requests=Vec::new();
    let colors=["blue", "green", "sienna", "purple", "slate", "gray", "amber", "ochre"];
    let cities=["New+York", "San%20Jose", "Paris", "Cape+Town", "Lisbon", "Quebec", "Aarhus", "York"];
    for (n,color) in colors.iter().enumerate() {
        for kind in 0..3 {
            let mut headers=vec![
                ("Host".into(), "example.test".into()),
                ("User-Agent".into(), "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0".into()),
                ("Accept".into(), "application/json".into()),
                ("X-Label".into(), color.to_string()),
                ("X-Label".into(), format!("sample-{n}")),
            ];
            let (method,path,ctype,body)=match kind {
                0=>("GET","/api/catalog","",String::new()),
                1=>("POST","/api/forms","application/x-www-form-urlencoded",format!("name={color}&city={}&note=tea%20%26%20toast&units={}",cities[n],n+1)),
                _=>("POST","/api/orders","application/json",format!(r#"{{"color":"{color}","items":[{{"units":{},"size":"small"}}],"gift":false}}"#,n+1)),
            };
            if !ctype.is_empty() {
                headers.push(("Content-Type".into(),ctype.into()));
                headers.push(("Content-Length".into(),body.len().to_string()));
            }
            let uri=format!("{path}?page={}&tag={color}&tag=seasonal&city={}",n+1,cities[n]);
            requests.push(Request{kind,uri,method,headers,body});
        }
    }
    requests
}

fn observe(buf: &mut String, t: &Transaction, phase: &str) {
    writeln!(buf, "{} ids={:?} audit={:?} intervention={:?}",phase,t.matched_rules(),t.matched_data(),t.intervention()).unwrap();
    writeln!(buf, "tx={:?} score={} blocked={} setvars={:?} messages={:?}",t.tx().all_bytes(),t.anomaly_score(),t.has_intervention(),t.setvar_effects(),t.rule_messages()).unwrap();
    writeln!(buf, "request=({}, {}) response=({}, {}, {})",t.request_body_accessible(),t.request_body_buffered_len(),t.response_body_accessible(),t.response_body_processable(),t.response_body_buffered_len()).unwrap();
}
fn evaluate(engine:&ModSecurity,r:&Request,lazy:bool,worker:usize)->String {
    let mut tx=engine.new_transaction();
    let mut out=String::new();
    // Odd workers preseed a public key; empty transactions exercise the compiled prefix.
    if worker%2==1 {tx.tx_mut().set_bytes("private_worker",worker.to_string());}
    tx.set_client_addr("10.0.0.1",40000);tx.set_server_addr("10.0.0.2",443);
    tx.set_server_name("example.test");
    if !lazy{observe(&mut out,&tx,"empty");}
    tx.process_uri(&r.uri,r.method,"HTTP/1.1").unwrap();
    for (name,value) in &r.headers {tx.add_request_header(name,value).unwrap();}
    tx.process_request_headers().unwrap();
    if !lazy{observe(&mut out,&tx,"request headers");}
    if !r.body.is_empty(){writeln!(out,"body write {:?}",tx.write_request_body(r.body.as_bytes()).unwrap()).unwrap();}
    tx.process_request_body().unwrap();
    if !lazy{observe(&mut out,&tx,"request body");}
    tx.add_response_header("Content-Type","text/plain").unwrap();
    tx.process_response_headers_with_status(200,"HTTP/1.1").unwrap();
    if !lazy{observe(&mut out,&tx,"response headers");}
    writeln!(out,"response write {:?}",tx.write_response_body(b"catalog response").unwrap()).unwrap();
    tx.process_response_body().unwrap();
    if !lazy{observe(&mut out,&tx,"response body");}
    tx.process_logging().unwrap();
    observe(&mut out,&tx,"logging");
    out
}
fn main() {
    let root=std::env::args().nth(1).unwrap();
    let cfg=format!("SecRuleEngine On\nSecRequestBodyAccess On\nInclude \"{root}/crs-setup.conf.example\"\nInclude \"{root}/rules/*.conf\"\n");
    let e=ModSecurity::from_string(&cfg).unwrap();assert_eq!(e.rule_count(),698);
    let rs=requests();assert_eq!(rs.len(),24);
    let workers=4;
    let one=|worker:usize|{let mut out=String::new();for (i,r) in rs.iter().enumerate(){for lazy in [false,true]{
        writeln!(out,"fixture {worker} {i} {} {lazy}",r.kind).unwrap();out.push_str(&evaluate(&e,r,lazy,worker));
    }}out};
    let serial=(0..workers).map(one).collect::<Vec<_>>();
    let gate=Arc::new(Barrier::new(workers));
    std::thread::scope(|scope|{
        let threads=(0..workers).map(|id|{let gate=gate.clone();scope.spawn(move||{gate.wait();one(id)})}).collect::<Vec<_>>();
        for (w,t) in threads.into_iter().enumerate(){assert!(t.join().unwrap()==serial[w],"worker {w} mismatch");}
    });
    for data in serial {print!("{data}");}
}
