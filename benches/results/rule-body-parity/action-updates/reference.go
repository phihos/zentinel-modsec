package main
import("fmt";"github.com/corazawaf/coraza/v3")
func main(){
 rules:=`SecRuleEngine On
SecRule REQUEST_URI "@rx ^(/ok)$" "id:11,phase:1,pass,msg:'original',log,setvar:tx.first=1"
SecRule REQUEST_URI "@rx ^(/ok)$" "id:12,phase:1,pass,msg:'original2',log,setvar:tx.second=1"`
 for _,edit:=range []string{`11 "deny,status:409"`,`11-12 "deny,status:410"`,`11-12 "setvar:tx.edited=1,msg:'edited',capture,tag:new"`,`99-100 deny`,`99-99 deny`,`11 12 "deny"`,`10-11 12-13 "msg:changed"`,`11 "deny, status:410"`,`11 "deny:extra"`,`11 "deny,"`,`11 ""`,`11 'deny'`,`"11" "deny"`,`11 "phase:2"`,`11 "id:14"`,`11 "id:12"`,`11 "msg:'new label'"`,`11 "setvar:tx.edited=1"`,`11 "skip:1"`,`11 "chain"`,`11 "nolog"`,`11 "block,status:409"`,`11 "allow:phase"`,`11 "drop"`,`11 "t:none,t:uppercase"`,`11 "pass,deny"`,`11 "deny,pass"`,`11 "deny" "pass"`,`11-10 deny`,`11 99 broken!`,`11 ""`,`11-12 status:-1`,`11-12 bad`,`11-12 msg:`,`11-12 "id:23"`}{
  cfg:=rules+"\nSecRuleUpdateActionById "+edit+"\n"+`SecRule TX:edited "@streq 1" "id:21,phase:2,pass,msg:edited,log"`+"\n"+`SecRule TX:1 "@streq /ok" "id:22,phase:2,pass,msg:cap,log"`
  w,e:=coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(cfg));if e!=nil{fmt.Println(edit,"LOAD ERROR",e);continue};tx:=w.NewTransaction();tx.ProcessURI("/ok","GET","HTTP/1.1");it:=tx.ProcessRequestHeaders();phase1:=[]int{};for _,r:=range tx.MatchedRules(){phase1=append(phase1,r.Rule().ID())};if it==nil{it,_=tx.ProcessRequestBody()};status:=0;if it!=nil{status=it.Status};ids:=[]int{};msgs:=[]string{};for _,r:=range tx.MatchedRules(){ids=append(ids,r.Rule().ID());msgs=append(msgs,r.Message())};fmt.Println(edit,"status",status,"phase1",phase1,"all",ids,"messages",msgs);tx.Close()
 }
}
