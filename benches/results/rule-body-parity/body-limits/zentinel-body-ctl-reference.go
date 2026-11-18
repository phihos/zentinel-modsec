package main
import("fmt";"github.com/corazawaf/coraza/v3")
func main(){
for _,direction:=range []string{"request","response"} {
for _,action:=range []string{"Reject","ProcessPartial"}{
for _,limit:=range []string{"0","4","12"} {
for _,chunk:=range []string{"ab","abcd","abcdefghi","abcdefghijkl"}{
 phase:=1; if direction=="response"{phase=3}
 cfg:=fmt.Sprintf("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\nSecRequestBodyLimit 8\nSecResponseBodyLimit 8\nSecRequestBodyLimitAction %s\nSecResponseBodyLimitAction %s\nSecAction \"id:1,phase:%d,pass,nolog,ctl:%sBodyLimit=%s\"\nSecRule INBOUND_DATA_ERROR \"@streq 1\" \"id:2,phase:2,pass,log\"\nSecRule OUTBOUND_DATA_ERROR \"@streq 1\" \"id:3,phase:4,pass,log\"",action,action,phase,direction,limit)
 w,e:=coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(cfg));if e!=nil{panic(e)};t:=w.NewTransaction();t.ProcessURI("/","POST","HTTP/1.1");t.ProcessRequestHeaders()
 var n,status int; var err error
 if direction=="response"{t.ProcessRequestBody();t.AddResponseHeader("Content-Type","text/plain");t.ProcessResponseHeaders(200,"HTTP/1.1");it,i,e:=t.WriteResponseBody([]byte(chunk));n,err=i,e;if it!=nil{status=it.Status};t.ProcessResponseBody()}else{it,i,e:=t.WriteRequestBody([]byte(chunk));n,err=i,e;if it!=nil{status=it.Status};t.ProcessRequestBody()}
 matched:=[]int{};for _,r:=range t.MatchedRules(){if r.Rule().ID()!=1{matched=append(matched,r.Rule().ID())}};fmt.Println(direction,action,limit,len(chunk),"consumed",n,"status",status,"error",err,"flagmatch",matched);t.Close()
}}}}}
