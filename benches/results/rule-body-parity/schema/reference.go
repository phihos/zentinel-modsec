package main

import (
	"encoding/json"
	"fmt"
	coraza "github.com/corazawaf/coraza/v3"
	"net/url"
	"os"
	"strings"
	"testing/fstest"
)

func nested(s string, n int) string { return strings.Repeat("[", n) + s + strings.Repeat("]", n) }
func main() {
	out, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer out.Close()
	finite := `{"$defs":{"entry":{"type":"object","required":["kind","detail"],"properties":{"kind":{"enum":["book","album"]},"detail":{"anyOf":[{"const":{"label":[]}},{"type":"array","minItems":1}]}}}},"type":"object","required":["entries"],"properties":{"entries":{"type":"array","items":{"$ref":"#/$defs/entry"}}}}`
	check := func(schema, doc, label string, invalid bool) {
		if err := json.NewEncoder(out).Encode([]string{label, schema, doc}); err != nil {
			panic(err)
		}
		config := `SecRuleEngine DetectionOnly
SecRule ARGS:q "@validateSchema schema.json" "id:1,phase:1,pass,log"`
		waf, e := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(fstest.MapFS{"schema.json": &fstest.MapFile{Data: []byte(schema)}}).WithDirectives(config))
		if e != nil {
			panic(e)
		}
		tx := waf.NewTransaction()
		defer tx.Close()
		tx.ProcessURI("/?q="+url.QueryEscape(doc), "GET", "HTTP/1.1")
		tx.ProcessRequestHeaders()
		match := len(tx.MatchedRules()) > 0
		if match != invalid {
			panic(fmt.Sprintf("%s: got violation=%v, expected=%v", label, match, invalid))
		}
		fmt.Printf("%s violation=%v\n", label, match)
	}
	deep := nested("42", 240)
	for i, c := range []struct {
		k, d    string
		invalid bool
	}{{"book", deep, false}, {"unknown", deep, true}, {"album", nested("2e400", 240), true}, {"book", `{"label":` + deep + "}", true}, {"book", deep + "X", true}, {"book", "[]", true}} {
		check(finite, `{"metadata":`+deep+`,"entries":[{"kind":"`+c.k+`","detail":`+c.d+`}]}`, fmt.Sprintf("compound-%d", i), c.invalid)
	}
	check(`{"type":"array","uniqueItems":true}`, "["+nested("1", 160)+","+nested("2", 160)+"]", "deep-unique-distinct", false)
	check(`{"type":"array","uniqueItems":true}`, "["+nested("1", 160)+","+nested("1", 160)+"]", "deep-unique-duplicate", true)
	for _, v := range []struct {
		first, second, label string
		equal                bool
	}{
		{"1", "1.0", "numeric", true},
		{`{"a":1,"b":"x"}`, `{"b":"\u0078","a":1.0}`, "object-order-and-escape", true},
		{`{"a":0,"a":1}`, `{"a":1}`, "duplicate-key", true},
		{`{"a":1}`, `{"b":1}`, "different-key", false},
		{"-0.0", "0", "negative-zero", false},
	} {
		check(`{"type":"array","uniqueItems":true}`, "["+nested(v.first, 160)+","+nested(v.second, 160)+"]", "deep-unique-"+v.label, v.equal)
	}
	check(`{"type":"array","uniqueItems":true}`, "[-0.0,0]", "shallow-unique-negative-zero", false)
	selection := `{"$defs":{"distinct":{"uniqueItems":true}},"properties":{"count":{"const":0},"unchecked":{"uniqueItems":false},"list":{"if":{"type":"array"},"then":{"$ref":"#/$defs/distinct"}}}}`
	for i, c := range []struct {
		list      string
		violation bool
	}{
		{"[-0.0,0,1]", false}, {"[-0.0,0,1,1.0]", true}, {"[-0.0,-0]", true},
		{`[{"a":-0,"b":0},{"b":-0,"a":0}]`, false}, {`[{"a":-0,"b":0},{"b":0,"a":-0.0}]`, true}, {`"value"`, false},
	} {
		check(selection, `{"count":-0.0,"unchecked":[0,0],"list":`+c.list+"}", fmt.Sprintf("selected-array-%d", i), c.violation)
	}
	recursive := `{"$defs":{"list":{"anyOf":[{"type":"integer"},{"type":"array","items":{"$ref":"#/$defs/list"}}]}},"$ref":"#/$defs/list"}`
	check(recursive, nested("42", 160), "recursive-integer", false)
	check(recursive, nested(`"book"`, 160), "recursive-string", true)
}
