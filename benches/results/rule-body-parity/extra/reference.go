// Run with the pinned Go module in zentinel-eval/scripts/ftw; pass fixtures.json.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fixture struct {
	Name, Rules, Body string
	Headers           [][2]string
	Upload            bool
	PathArgs          [][2]string
	URI               string
}
type outcome struct {
	Name             string   `json:"name"`
	Loaded           bool     `json:"loaded"`
	Matches          []string `json:"matches"`
	Files, Remaining []string
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func files(dir string) []string {
	entries, e := os.ReadDir(dir)
	must(e)
	out := []string{}
	for _, entry := range entries {
		b, e := os.ReadFile(filepath.Join(dir, entry.Name()))
		must(e)
		out = append(out, hex.EncodeToString(b))
	}
	sort.Strings(out)
	return out
}
func check(f fixture) outcome {
	dir, e := os.MkdirTemp("", "zentinel-extra-")
	must(e)
	defer os.RemoveAll(dir)
	r := outcome{Name: f.Name, Matches: []string{}, Files: []string{}, Remaining: []string{}}
	w, e := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine DetectionOnly\n" + strings.ReplaceAll(f.Rules, "{DIR}", dir)))
	if e != nil {
		return r
	}
	r.Loaded = true
	t := w.NewTransaction()
	if f.URI == "" {
		f.URI = "/"
	}
	t.ProcessURI(f.URI, "GET", "HTTP/1.1")
	for _, p := range f.PathArgs {
		t.AddPathRequestArgument(p[0], p[1])
	}
	for _, h := range f.Headers {
		t.AddRequestHeader(h[0], h[1])
	}
	t.ProcessRequestHeaders()
	if f.Body != "" {
		_, _, e = t.WriteRequestBody([]byte(f.Body))
		must(e)
	}
	_, e = t.ProcessRequestBody()
	must(e)
	t.ProcessLogging()
	for _, m := range t.MatchedRules() {
		msg := m.Message()
		if f.Upload && msg != "" {
			if filepath.Dir(msg) != dir {
				panic("unexpected temporary-file path")
			}
			b, e := os.ReadFile(msg)
			must(e)
			msg = hex.EncodeToString(b)
		}
		r.Matches = append(r.Matches, fmt.Sprintf("%d=%s", m.Rule().ID(), msg))
	}
	if f.Upload {
		r.Files = files(dir)
	}
	must(t.Close())
	if f.Upload {
		r.Remaining = files(dir)
	}
	return r
}
func main() {
	data, e := os.ReadFile(os.Args[1])
	must(e)
	var fs []fixture
	must(json.Unmarshal(data, &fs))
	out := []outcome{}
	for _, f := range fs {
		out = append(out, check(f))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(out))
}
