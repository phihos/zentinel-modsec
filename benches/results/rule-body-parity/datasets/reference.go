package main

import (
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"os"
)

func main() {
	group := func(name, records string) string { return "SecDataset " + name + " `\n" + records + "\n`\n" }
	rule := func(id int, op, ds string) string {
		return fmt.Sprintf("SecRule ARGS:q \"@%s %s\" \"id:%d,phase:1,pass,log,capture,msg:'%%{tx.0}'\"\n", op, ds, id)
	}
	tests := []struct{ name, config string }{
		{"phrases", group("Words", "  # note\nblUE\nblue sky\nword #keep") + rule(1, "pmFromDataset", "Words")},
		{"duplicate", group("Words", "blue") + rule(1, "pmFromDataset", "Words") + group("Words", "green") + rule(2, "pmFromDataset", "Words")},
		{"wrongcase", group("Words", "blue") + rule(1, "pmFromDataset", "words")},
		{"forward", rule(1, "pmFromDataset", "Words") + group("Words", "blue")},
		{"empty-phrase", group("empty", " # ignored") + rule(1, "pmFromDataset", "empty")},
		{"empty-ip", group("empty", " # ignored") + rule(1, "ipMatchFromDataset", "empty")},
		{"ips", group("N", "192.0.2.0/24,2001:db8::8\n198.51.100.2") + "SecAction \"id:20,phase:1,pass,setvar:tx.0=old\"\n" + rule(1, "ipMatchFromDataset", "N")},
		{"bad-ip", group("N", "192.0.2.1,nope") + rule(1, "ipMatchFromDataset", "N")},
		{"comma", group("N", "192.0.2.1,") + rule(1, "ipMatchFromDataset", "N")},
		{"space", group("N", "192.0.2.1 192.0.2.2") + rule(1, "ipMatchFromDataset", "N")},
		{"inline", "SecDataset X blue sky\n" + rule(1, "pmFromDataset", "X")},
		{"missing-body", "SecDataset X\n"},
		{"unclosed", "SecDataset X `\nblue"},
		{"backtick-one-line", "SecDataset X `blue sky`\n" + rule(1, "pmFromDataset", "X")},
	}
	for _, tc := range tests {
		if len(os.Args) > 1 && os.Args[1] != tc.name {
			continue
		}
		w, e := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine DetectionOnly\n" + tc.config))
		if e != nil {
			fmt.Printf("%s: ERROR %s\n", tc.name, e)
			continue
		}
		fmt.Printf("%s:", tc.name)
		for _, q := range []string{"BLUE+SKY", "green", "192.0.2.1", "2001:db8::8", "word+%23keep", "none"} {
			t := w.NewTransaction()
			t.ProcessURI("/?q="+q, "GET", "HTTP/1.1")
			t.ProcessRequestHeaders()
			for _, m := range t.MatchedRules() {
				fmt.Printf(" %s/%d/%q", q, m.Rule().ID(), m.Message())
			}
			t.Close()
		}
		fmt.Println()
	}
}
