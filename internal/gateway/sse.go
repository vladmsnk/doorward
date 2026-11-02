package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/vladmsnk/doorward/internal/x"
)

// filterTools rewrites a tools/list response, plain JSON or an event
// stream, keeping only the tools rw.filter allows.
func filterTools(res *http.Response, rw *rewrite) error {
	ct := res.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/json"):
		body, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil {
			return err
		}
		out := rewriteToolList(body, rw)
		res.Body = io.NopCloser(bytes.NewReader(out))
		res.ContentLength = int64(len(out))
		res.Header.Set("Content-Length", strconv.Itoa(len(out)))
		return nil
	case strings.HasPrefix(ct, "text/event-stream"):
		pr, pw := io.Pipe()
		src := res.Body
		go func() {
			defer func() { _ = src.Close() }()
			err := rewriteEvents(src, pw, func(data []byte) []byte { return rewriteToolList(data, rw) })
			_ = pw.CloseWithError(err)
		}()
		res.Body = pr
		res.ContentLength = -1
		res.Header.Del("Content-Length")
		return nil
	}
	return nil
}

// rewriteToolList filters result.tools in a JSON-RPC response for rw.id;
// anything else is returned as it came.
func rewriteToolList(data []byte, rw *rewrite) []byte {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Result map[string]json.RawMessage
	}
	if err := json.Unmarshal(data, &msg); err != nil || msg.Result == nil {
		return data
	}
	if rw.id != nil && !bytes.Equal(bytes.TrimSpace(msg.ID), bytes.TrimSpace(rw.id)) {
		return data
	}
	rawTools, ok := msg.Result["tools"]
	if !ok {
		return data
	}
	var tools []map[string]any
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return data
	}
	kept := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		if name, _ := t["name"].(string); rw.filter(name) {
			kept = append(kept, t)
		}
	}
	var whole map[string]json.RawMessage
	if err := json.Unmarshal(data, &whole); err != nil {
		return data
	}
	result := msg.Result
	result["tools"], _ = json.Marshal(kept)
	whole["result"], _ = json.Marshal(result)
	out, err := json.Marshal(whole)
	if err != nil {
		return data
	}
	return out
}

// rewriteEvents copies an SSE stream, applying fn to each event's data and
// writing event by event. Field lines other than data pass unchanged.
func rewriteEvents(r io.Reader, w io.Writer, fn func([]byte) []byte) error {
	return x.ReadEvents(r, MaxBody, func(e x.Event) error {
		var out bytes.Buffer
		for _, l := range e.Fields {
			out.WriteString(l + "\n")
		}
		if e.Data != nil {
			data := e.Data
			if len(bytes.TrimSpace(data)) > 0 {
				data = fn(data)
			}
			for _, line := range bytes.Split(data, []byte("\n")) {
				out.WriteString("data: ")
				out.Write(line)
				out.WriteByte('\n')
			}
		}
		out.WriteByte('\n')
		_, err := w.Write(out.Bytes())
		return err
	})
}
