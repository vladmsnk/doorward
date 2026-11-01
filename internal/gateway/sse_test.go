package gateway

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRewriteEvents(t *testing.T) {
	keep := func(tool string) bool { return tool != "export_everything" }
	rw := &rewrite{id: json.RawMessage(`3`), filter: keep}
	in := strings.Join([]string{
		"id: a1",
		"data: ",
		"",
		": a comment",
		"event: message",
		"id: a2",
		`data: {"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"post_entry"},`,
		`data: {"name":"export_everything"}]}}`,
		"",
		"event: message",
		`data: {"jsonrpc":"2.0","id":4,"result":{"tools":[{"name":"export_everything"}]}}`,
		"",
		"event: message",
		`data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`,
		"",
		"",
	}, "\n")
	var out bytes.Buffer
	if err := rewriteEvents(strings.NewReader(in), &out, func(d []byte) []byte { return rewriteToolList(d, rw) }); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	want := strings.Join([]string{
		"id: a1",
		"data: ",
		"",
		": a comment",
		"event: message",
		"id: a2",
		`data: {"id":3,"jsonrpc":"2.0","result":{"tools":[{"name":"post_entry"}]}}`,
		"",
		"event: message",
		`data: {"jsonrpc":"2.0","id":4,"result":{"tools":[{"name":"export_everything"}]}}`,
		"",
		"event: message",
		`data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`,
		"",
		"",
	}, "\n")
	if got != want {
		t.Errorf("rewritten stream:\n%s\nwant:\n%s", got, want)
	}
}

func TestRewriteToolListLeavesOtherMessages(t *testing.T) {
	rw := &rewrite{filter: func(string) bool { return false }}
	for _, in := range []string{
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}`,
		`not json`,
	} {
		if got := string(rewriteToolList([]byte(in), rw)); got != in {
			t.Errorf("%s became %s", in, got)
		}
	}
	in := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}],"nextCursor":"x"}}`
	var got map[string]any
	if err := json.Unmarshal(rewriteToolList([]byte(in), rw), &got); err != nil {
		t.Fatal(err)
	}
	res := got["result"].(map[string]any)
	if tools := res["tools"].([]any); len(tools) != 0 || res["nextCursor"] != "x" {
		t.Errorf("filtered list: %v", got)
	}
}
