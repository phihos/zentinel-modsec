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
	for _, connect := range []bool{false, true} {
		t := w.NewTransaction()
		if connect {
			t.ProcessConnection("127.0.0.1", 0, "127.0.0.1", 8443)
		}
		t.ProcessURI("/docs/index?=zero&Name=first", "POST", "HTTP/1.1")
		t.AddRequestHeader("X-Test", "alpha")
		t.AddRequestHeader("Cookie", "Name=value")
		t.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		t.ProcessRequestHeaders()
		t.WriteRequestBody([]byte("lang=en"))
		t.ProcessRequestBody()
		t.AddResponseHeader("Content-Type", "text/plain; charset=utf-8")
		t.AddResponseHeader("X-Server", "beta")
		t.ProcessResponseHeaders(203, "HTTP/2")
		t.WriteResponseBody([]byte{0xff, 'k'})
		t.ProcessResponseBody()
		for _, m := range t.MatchedRules() {
			fmt.Printf("%v/%d %q %q\n", connect, m.Rule().ID(), m.Message(), m.Data())
		}
		t.Close()
	}
}
