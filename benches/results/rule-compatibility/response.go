package main

import (
	"fmt"
	coraza "github.com/corazawaf/coraza/v3"
)

func main() {
	for _, c := range []struct {
		access, media, force string
		selected             bool
	}{
		{"On", "text/csv", "ctl:forceResponseBodyVariable=oN", true}, {"On", "", "ctl:forceResponseBodyVariable=On", true},
		{"Off", "text/csv", "ctl:forceResponseBodyVariable=On", true},
		{"On", "text/csv", "ctl:forceResponseBodyVariable=On,ctl:forceResponseBodyVariable=OFF", false},
		{"On", "text/plain", "ctl:forceResponseBodyVariable=Off", true},
	} {
		cfg := fmt.Sprintf(`SecRuleEngine DetectionOnly
SecResponseBodyAccess %s
SecResponseBodyMimeType text/plain
SecRule RESPONSE_STATUS "@streq 200" "id:1,phase:3,pass,log,%s"
SecRule RESPONSE_BODY "@streq hello" "id:2,phase:4,pass,log"
SecRule RESPONSE_CONTENT_LENGTH "@eq 5" "id:3,phase:4,pass,log"`, c.access, c.force)
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(cfg))
		if err != nil {
			panic(err)
		}
		for _, early := range []bool{true, false} {
			tx := waf.NewTransaction()
			tx.ProcessURI("/", "GET", "HTTP/1.1")
			tx.ProcessRequestHeaders()
			tx.ProcessRequestBody()
			if c.media != "" {
				tx.AddResponseHeader("Content-Type", c.media)
			}
			data := "hello"
			if early {
				_, n, e := tx.WriteResponseBody([]byte("he"))
				if e != nil || n != map[bool]int{true: 2, false: 0}[c.access == "On"] {
					panic(fmt.Sprint("pre-header write", n, e))
				}
				data = "llo"
			}
			tx.ProcessResponseHeaders(200, "HTTP/1.1")
			if tx.IsResponseBodyProcessable() != c.selected {
				panic("MIME selection mismatch")
			}
			tx.WriteResponseBody([]byte(data))
			tx.ProcessResponseBody()
			var ids []int
			for _, m := range tx.MatchedRules() {
				ids = append(ids, m.Rule().ID())
			}
			expected := "[1]"
			if c.selected && c.access == "On" {
				expected = "[1 2 3]"
			}
			if fmt.Sprint(ids) != expected {
				panic(fmt.Sprintf("%s %s %v: got %v want %s", c.access, c.media, early, ids, expected))
			}
			fmt.Printf("access=%s mime=%q %s early=%v selected=%v ids=%v\n", c.access, c.media, c.force, early, c.selected, ids)
			tx.Close()
		}
	}
}
