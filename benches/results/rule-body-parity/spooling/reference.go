// Run with TMPDIR pointing at an empty directory. Linux /proc/self/fd also
// records anonymous open files so the same observation works across backends.
package main

import (
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"os"
	"path/filepath"
	"strings"
)

func backing() int {
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		panic(e)
	}
	n := 0
	for _, entry := range entries {
		target, e := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if e == nil && strings.HasPrefix(target, os.Getenv("TMPDIR")+"/") {
			n++
		}
	}
	return n
}
func main() {
	w, e := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit 16
SecRequestBodyInMemoryLimit 3
SecRule ARGS_POST:x "@streq abcdef" "id:1,phase:2,pass"`))
	if e != nil {
		panic(e)
	}
	t := w.NewTransaction()
	t.ProcessURI("/", "POST", "HTTP/1.1")
	t.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	t.ProcessRequestHeaders()
	for _, chunk := range []string{"x=a", "bc", "def"} {
		_, n, e := t.WriteRequestBody([]byte(chunk))
		if e != nil {
			panic(e)
		}
		fmt.Printf("consumed=%d file=%t\n", n, backing() != 0)
	}
	t.ProcessRequestBody()
	for _, r := range t.MatchedRules() {
		fmt.Printf("phase2=%d\n", r.Rule().ID())
	}
	if e = t.Close(); e != nil {
		panic(e)
	}
	fmt.Printf("closed=%t\n", backing() == 0)
}
