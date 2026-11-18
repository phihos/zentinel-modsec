package main

import (
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"os"
)

func main() {
	rules, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(string(rules)))
	if err != nil {
		panic(err)
	}
	for _, uri := range []string{"/x/orders/grocery/tea", "/x/orders/grocery/tea?Item=query", "/x/no-route"} {
		t := w.NewTransaction()
		t.ProcessURI(uri, "GET", "HTTP/1.1")
		t.ProcessRequestHeaders()
		t.ProcessRequestBody()
		fmt.Print(uri)
		for _, m := range t.MatchedRules() {
			fmt.Printf(" %d=%q", m.Rule().ID(), m.Message())
		}
		fmt.Println()
		t.Close()
	}
}
