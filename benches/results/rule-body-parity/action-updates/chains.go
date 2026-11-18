package main
import("fmt";"github.com/corazawaf/coraza/v3")
func main(){for _,cfg:=range []string{
`SecRule REQUEST_URI "@streq /ok" "id:11,phase:1,pass,chain"
SecRuleUpdateActionById 11 deny`,
`SecAction "id:11,phase:1,pass,chain"
SecRule REQUEST_METHOD "@streq GET" "setvar:tx.seen=1"
SecRuleUpdateActionById 11 deny`,
`SecRule REQUEST_METHOD "@streq GET" "id:11,phase:1,chain,pass"
SecAction "setvar:tx.seen=1"
SecRuleUpdateActionById 11 deny`,
`SecRule REQUEST_URI "@streq /ok" "id:11,phase:1,deny"
SecRuleUpdateActionById 11 chain
SecRule REQUEST_METHOD "@streq POST" "id:12,phase:1,pass"`,
`SecRule REQUEST_URI "@streq /ok" "id:11,phase:1,deny"
SecRuleUpdateActionById 11 chain
SecRule REQUEST_METHOD "@streq POST" "pass"`,
`SecRule REQUEST_URI "@streq /ok" "id:11,phase:1,deny"
SecRuleUpdateActionById 11 block`,
}{w,e:=coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\n"+cfg));if e!=nil{fmt.Println("LOAD ERROR",e);continue};tx:=w.NewTransaction();tx.ProcessURI("/ok","GET","HTTP/1.1");it:=tx.ProcessRequestHeaders();fmt.Println("interrupt",it,"matches",len(tx.MatchedRules()));tx.Close()}}
