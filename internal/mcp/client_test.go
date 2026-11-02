package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vladmsnk/doorward/internal/demoledger"
	"github.com/vladmsnk/doorward/internal/mcp"
)

const apiKey = "lk_live_example"

var credential = http.Header{"Authorization": {"Bearer " + apiKey}}

func names(tools []mcp.Tool) string {
	var out []string
	for _, t := range tools {
		out = append(out, t.Name)
	}
	return strings.Join(out, ",")
}

// headers records what each request to h carried.
type headers struct {
	mu   sync.Mutex
	seen []http.Header
	h    http.Handler
}

func (s *headers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.seen = append(s.seen, r.Header.Clone())
	s.mu.Unlock()
	s.h.ServeHTTP(w, r)
}

func TestListToolsFromTheDemoLedger(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ledger *demoledger.Server
		posts  int // initialize, initialized, then one tools/list per page
	}{
		{"json", &demoledger.Server{APIKey: apiKey}, 3},
		{"event stream", &demoledger.Server{APIKey: apiKey, SSE: true}, 3},
		{"pages", &demoledger.Server{APIKey: apiKey, PageSize: 1}, 6},
		{"pages as event streams", &demoledger.Server{APIKey: apiKey, SSE: true, PageSize: 3}, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &headers{h: tc.ledger}
			srv := httptest.NewServer(rec)
			defer srv.Close()
			l, err := mcp.ListTools(context.Background(), srv.URL, credential)
			if err != nil {
				t.Fatal(err)
			}
			if got := names(l.Tools); got != "list_unmatched,post_entry,write_off,export_everything" {
				t.Errorf("tools: %s", got)
			}
			if l.Server != (mcp.Server{Name: "demo-ledger", Version: "0.1", Protocol: mcp.ProtocolVersion}) {
				t.Errorf("server: %+v", l.Server)
			}
			ro := l.Tools[0].Annotations
			if ro == nil || ro.ReadOnlyHint == nil || !*ro.ReadOnlyHint || ro.DestructiveHint != nil {
				t.Errorf("list_unmatched's annotations: %+v", ro)
			}
			if l.Tools[1].Annotations != nil {
				t.Errorf("post_entry has no annotations, got %+v", l.Tools[1].Annotations)
			}
			var schema struct {
				Properties map[string]any `json:"properties"`
			}
			if err := json.Unmarshal(l.Tools[1].InputSchema, &schema); err != nil || len(schema.Properties) != 3 {
				t.Errorf("post_entry's input schema: %s", l.Tools[1].InputSchema)
			}

			var methods []string
			for _, s := range tc.ledger.Requests() {
				methods = append(methods, s.Method)
				if s.Credential != "api key" {
					t.Errorf("%s carried %s", s.Method, s.Credential)
				}
			}
			if len(methods) != tc.posts+1 || methods[0] != "initialize" || methods[1] != "notifications/initialized" || methods[len(methods)-1] != "DELETE" {
				t.Errorf("requests: %v", methods)
			}
			// After the handshake every request names the session and the
			// revision agreed on.
			for i, h := range rec.seen[1:] {
				if h.Get("Mcp-Session-Id") == "" || h.Get("Mcp-Protocol-Version") != mcp.ProtocolVersion {
					t.Errorf("request %d: session %q, version %q", i+2, h.Get("Mcp-Session-Id"), h.Get("Mcp-Protocol-Version"))
				}
			}
		})
	}
}

func TestListToolsWithoutTheCredential(t *testing.T) {
	srv := httptest.NewServer(&demoledger.Server{APIKey: apiKey})
	defer srv.Close()
	_, err := mcp.ListTools(context.Background(), srv.URL, nil)
	var se *mcp.StatusError
	if !errors.As(err, &se) || !se.Unauthorized() || se.Method != "initialize" {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "wants its API key") {
		t.Errorf("err = %v", err)
	}
}

// server is an MCP server that shakes hands and answers tools/list with
// list, given the request's cursor.
func server(t *testing.T, list func(w http.ResponseWriter, id json.RawMessage, cursor string)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&msg)
		switch msg.Method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"test\u001b[31m","version":"1"}}}`, msg.ID)
		case "tools/list":
			list(w, msg.ID, msg.Params.Cursor)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func page(w http.ResponseWriter, id json.RawMessage, result string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, id, result)
}

func TestListToolsFromAHostileServer(t *testing.T) {
	for _, tc := range []struct {
		name string
		list func(w http.ResponseWriter, id json.RawMessage, cursor string)
		want string
	}{
		{"endless pages", func(w http.ResponseWriter, id json.RawMessage, cursor string) {
			page(w, id, fmt.Sprintf(`{"tools":[],"nextCursor":"%s+"}`, cursor))
		}, "runs past 100 pages"},
		{"a cursor again", func(w http.ResponseWriter, id json.RawMessage, cursor string) {
			page(w, id, `{"tools":[],"nextCursor":"same"}`)
		}, "same cursor twice"},
		{"a tool twice", func(w http.ResponseWriter, id json.RawMessage, cursor string) {
			if cursor == "" {
				page(w, id, `{"tools":[{"name":"a"}],"nextCursor":"2"}`)
				return
			}
			page(w, id, `{"tools":[{"name":"a"}]}`)
		}, `lists tool "a" twice`},
		{"too many tools", func(w http.ResponseWriter, id json.RawMessage, cursor string) {
			tools := make([]string, 0, mcp.MaxTools+1)
			for i := range mcp.MaxTools + 1 {
				tools = append(tools, fmt.Sprintf(`{"name":"t%d"}`, i))
			}
			page(w, id, `{"tools":[`+strings.Join(tools, ",")+`]}`)
		}, "more than 1000 tools"},
		{"too large", func(w http.ResponseWriter, id json.RawMessage, cursor string) {
			page(w, id, `{"tools":[{"name":"a","description":"`+strings.Repeat("x", mcp.MaxMessage)+`"}]}`)
		}, "larger than"},
		{"an endless event stream", func(w http.ResponseWriter, id json.RawMessage, cursor string) {
			w.Header().Set("Content-Type", "text/event-stream")
			line := "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"
			for range mcp.MaxMessage/len(line) + 1 {
				if _, err := io.WriteString(w, line); err != nil {
					return
				}
			}
		}, "runs past"},
		{"a stream that ends without the answer", func(w http.ResponseWriter, id json.RawMessage, cursor string) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s99,\"result\":{\"tools\":[]}}\n\n", id)
		}, "ended without the response"},
		{"another content type", func(w http.ResponseWriter, id json.RawMessage, cursor string) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html>")
		}, `"text/html"`},
		{"an error", func(w http.ResponseWriter, id json.RawMessage, cursor string) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no tools\u0007 here"}}`, id)
		}, `answered -32601 "no tools  here"`},
		{"not a list", func(w http.ResponseWriter, id json.RawMessage, cursor string) {
			page(w, id, `{"tools":"many"}`)
		}, "not a tool list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mcp.ListTools(context.Background(), server(t, tc.list).URL, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestListToolsCleansWhatItPrints(t *testing.T) {
	srv := server(t, func(w http.ResponseWriter, id json.RawMessage, cursor string) {
		page(w, id, `{"tools":[{"name":"a"}]}`)
	})
	l, err := mcp.ListTools(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l.Server.Name != "test [31m" || l.Server.Protocol != "2025-06-18" {
		t.Errorf("server: %+v", l.Server)
	}
}

func TestListToolsGivesUpOnAStall(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	srv := server(t, func(w http.ResponseWriter, id json.RawMessage, cursor string) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "id: 1\ndata: \n\n")
		w.(http.Flusher).Flush()
		<-release
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := mcp.ListTools(ctx, srv.URL, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("gave up after %s", time.Since(start))
	}
}

func TestListToolsRefusesARedirect(t *testing.T) {
	var reached atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.RedirectHandler(elsewhere.URL+"/mcp", http.StatusTemporaryRedirect))
	defer srv.Close()
	_, err := mcp.ListTools(context.Background(), srv.URL, credential)
	if err == nil || !strings.Contains(err.Error(), "redirects to") || reached.Load() {
		t.Errorf("err = %v, the redirect followed: %v", err, reached.Load())
	}
}

func TestListToolsRefusesAnUnknownRevision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}`)
	}))
	defer srv.Close()
	_, err := mcp.ListTools(context.Background(), srv.URL, nil)
	if err == nil || !strings.Contains(err.Error(), `speaks MCP "2024-11-05"`) {
		t.Errorf("err = %v", err)
	}
}
