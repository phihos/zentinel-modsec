package main

import (
	"fmt"
	coraza "github.com/corazawaf/coraza/v3"
	"net/url"
	"strings"
	"testing/fstest"
)

func main() {
	schema := `{"type":"object","required":["ok"],"properties":{"ok":{"const":true}}}`
	cfg := `SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType application/json
SecAction "id:9,phase:1,pass,ctl:requestBodyProcessor=JSON"
SecAction "id:10,phase:3,pass,ctl:responseBodyProcessor=JSON"
SecRule RES_BODY_PROCESSOR "@streq JSON" "id:11,phase:3,pass,log"
SecRule RESPONSE_ARGS:json.title "@streq Book" "id:12,phase:4,pass,log"
SecRule &RESPONSE_ARGS:json.title "@eq 2" "id:13,phase:4,pass,log"
SecRule RESPONSE_BODY "@validateSchema reply.json" "id:14,phase:4,pass,log"
SecRule RESPONSE_CONTENT_LENGTH "@rx ^$" "id:15,phase:4,pass,log"
SecRule RESPONSE_BODY "@rx ^$" "id:16,phase:4,pass,log"
`
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(fstest.MapFS{"reply.json": &fstest.MapFile{Data: []byte(schema)}}).WithDirectives(cfg))
	if err != nil {
		panic(err)
	}
	for _, c := range []struct {
		response, media string
		ids             []int
	}{
		{`{"title":"Book","Title":"Other","ok":true}`, "application/json", []int{11, 12, 13, 15, 16}},
		{`{"ok":false}`, "application/json", []int{11, 14, 15, 16}},
		{`{"title":"Book","bad":`, "application/json", []int{11, 12, 14, 15, 16}},
		{`{"ok":true}`, "text/plain", []int{11, 14, 15, 16}},
	} {
		tx := waf.NewTransaction()
		tx.ProcessURI("/", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Content-Type", "application/json")
		tx.ProcessRequestHeaders()
		if _, _, err := tx.WriteRequestBody([]byte(`{"ok":false}`)); err != nil {
			panic(err)
		}
		if _, err := tx.ProcessRequestBody(); err != nil {
			panic(err)
		}
		tx.AddResponseHeader("Content-Type", c.media)
		tx.ProcessResponseHeaders(200, "HTTP/1.1")
		if _, _, err := tx.WriteResponseBody([]byte(c.response)); err != nil {
			panic(err)
		}
		if _, err := tx.ProcessResponseBody(); err != nil {
			panic(err)
		}
		var ids []int
		for _, matched := range tx.MatchedRules() {
			id := matched.Rule().ID()
			if id >= 11 {
				ids = append(ids, id)
			}
		}
		if fmt.Sprint(ids) != fmt.Sprint(c.ids) {
			panic(fmt.Sprintf("got %v want %v", ids, c.ids))
		}
		fmt.Printf("%s  %s  %v\n", c.media, c.response, ids)
		tx.Close()
	}

	deepPolicy := `SecRuleEngine DetectionOnly
SecRule ARGS:q "@validateSchema all.json" "id:1,phase:1,pass,log"`
	deepWaf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(fstest.MapFS{"all.json": &fstest.MapFile{Data: []byte("true")}}).WithDirectives(deepPolicy))
	if err != nil {
		panic(err)
	}
	for _, c := range []struct {
		scalar    string
		violation bool
	}{{`{"k":"a\"b","n":45}`, false}, {"2e400", true}, {"malformed", true}} {
		tx := deepWaf.NewTransaction()
		value := strings.Repeat("[", 160) + c.scalar + strings.Repeat("]", 160)
		tx.ProcessURI("/?q="+url.QueryEscape(value), "GET", "HTTP/1.1")
		tx.ProcessRequestHeaders()
		found := len(tx.MatchedRules()) > 0
		if found != c.violation {
			panic(fmt.Sprintf("%s: %v vs %v", c.scalar, found, c.violation))
		}
		fmt.Printf("160 nested arrays / %s: violation %v\n", c.scalar, found)
		tx.Close()
	}
}
