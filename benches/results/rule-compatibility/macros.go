package main

import (
	"fmt"
	"github.com/corazawaf/coraza/v3"
)

const rules = `SecRuleEngine DetectionOnly
SecAction "id:1,phase:1,pass,setvar:'tx.void=%{REQUEST_HEADERS.X-Empty}',setvar:'tx.values=%{Tx.MiSsInG}|%{rEqUeSt_HeAdErS.X-MiSs}|%{TX.VOID}|%{ReQuEsT_HeAdErS.X-EMPty}'"
SecRule ARGS:whole "@streq %{Tx.MiSsInG}" "id:2,phase:1,pass,log,msg:'%{Tx.MiSsInG}|%{rEqUeSt_HeAdErS.X-MiSs}|%{TX.VOID}|%{ReQuEsT_HeAdErS.X-EMPty}',logdata:'%{MATCHED_VAR}'"
SecRule ARGS:part "@within %{Tx.MiSsInG}" "id:3,phase:1,pass"
SecRule ARGS:part "@within %{Tx.Void}" "id:4,phase:1,pass"
SecRule TX:values "@streq Tx.MiSsInG|rEqUeSt_HeAdErS.X-MiSs||" "id:5,phase:1,pass"
SecRule ARGS:header "@streq %{rEqUeSt_HeAdErS.X-MiSs}" "id:6,phase:1,pass"
SecRule TX:values "@streq %{Tx.VoId}Tx.MiSsInG|rEqUeSt_HeAdErS.X-MiSs||%{ReQuEsT_HeAdErS.X-EMPty}" "id:7,phase:1,pass"
SecRule ARGS:empty_part "@within %{Tx.Void}" "id:8,phase:1,pass"`

func main() {
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(rules))
	if err != nil {
		panic(err)
	}
	t := w.NewTransaction()
	defer t.Close()
	t.ProcessURI("/?whole=Tx.MiSsInG&part=MiSs&header=rEqUeSt_HeAdErS.X-MiSs&empty_part=Void", "GET", "HTTP/1.1")
	t.AddRequestHeader("X-Empty", "")
	t.ProcessRequestHeaders()
	ids := []int{}
	for _, m := range t.MatchedRules() {
		ids = append(ids, m.Rule().ID())
		if m.Rule().ID() == 2 {
			fmt.Printf("msg=%q logdata=%q\n", m.Message(), m.Data())
			if m.Message() != "Tx.MiSsInG|rEqUeSt_HeAdErS.X-MiSs||" || m.Data() != "Tx.MiSsInG" {
				panic("messages")
			}
		}
	}
	fmt.Println("rules", ids)
	if fmt.Sprint(ids) != "[1 2 3 5 6 7]" {
		panic(ids)
	}
}
