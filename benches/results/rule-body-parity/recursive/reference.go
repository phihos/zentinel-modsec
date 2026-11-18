package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"os"
	"strings"
	"testing/fstest"
)

func main() {
	f, e := os.Open(os.Args[1])
	if e != nil {
		panic(e)
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 200000)
	for scan.Scan() {
		var row []json.RawMessage
		if e = json.Unmarshal(scan.Bytes(), &row); e != nil {
			panic(e)
		}
		var name, schema, doc string
		for i, field := range []*string{&name, &schema, &doc} {
			if e = json.Unmarshal(row[i], field); e != nil {
				panic(e)
			}
		}
		if strings.HasSuffix(name, "boundary") {
			continue
		}
		w, e := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(fstest.MapFS{"schema.json": &fstest.MapFile{Data: []byte(schema)}}).WithDirectives(`SecRuleEngine DetectionOnly
SecRule REQUEST_HEADERS:Sample "@validateSchema schema.json" "id:1,phase:1,pass"`))
		if e != nil {
			panic(e)
		}
		tx := w.NewTransaction()
		tx.AddRequestHeader("Sample", doc)
		tx.ProcessRequestHeaders()
		fmt.Printf("%s %t\n", name, len(tx.MatchedRules()) > 0)
		if e = tx.Close(); e != nil {
			panic(e)
		}
	}
	if e = scan.Err(); e != nil {
		panic(e)
	}
}
