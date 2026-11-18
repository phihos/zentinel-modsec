package main

import (
	"fmt"
	coraza "github.com/corazawaf/coraza/v3"
)

func main() {
	w, e := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\n" + `SecRule REQUEST_HEADERS:Example "@unconditionalMatch" "id:1,phase:1,pass,log,t:urlEncode,logdata:'%{MATCHED_VAR}'"`))
	if e != nil {
		panic(e)
	}
	input := make([]byte, 256)
	for i := range input {
		input[i] = byte(i)
	}
	t := w.NewTransaction()
	defer t.Close()
	t.ProcessURI("/", "GET", "HTTP/1.1")
	t.AddRequestHeader("Example", string(input))
	t.ProcessRequestHeaders()
	for _, m := range t.MatchedRules() {
		if m.Rule().ID() == 1 {
			for _, entry := range m.MatchedDatas() {
				fmt.Print(entry.Value())
			}
			return
		}
	}
	panic("missing match")
}
