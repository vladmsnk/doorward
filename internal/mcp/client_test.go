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
		pages  int
	}{
		{"json", &demoledger.Server{APIKey: apiKey}, 1},
		{"event stream", &demoledger.Server{APIKey: apiKey, SSE: true}, 1},
		{"pages", &demoledger.Server{APIKey: apiKey, PageSize: 1}, 4},
		{"pages as event streams", &demoledger.Server{APIKey: apiKey, SSE: true, PageSize: 3}, 2},
		{"an earlier revision", &demoledger.Server{APIKey: apiKey, Legacy: true}, 1},
		{"an earlier revision, pages as event streams", &demoledger.Server{APIKey: apiKey, Legacy: true, SSE: true, PageSize: 3}, 2},
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
			protocol := mcp.ProtocolVersion
			if tc.ledger.Legacy {
				protocol = "2025-11-25"
			}
			if l.Server != (mcp.Server{Name: "demo-ledger", Version: "0.1", Protocol: protocol}) {
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
			want := []string{"server/discover"}
			if tc.ledger.Legacy {
				want = append(want, "initialize", "notifications/initialized")
			}
			for range tc.pages {
				want = append(want, "tools/list")
			}
			if tc.ledger.Legacy {
				want = append(want, "DELETE")
			}
			if strings.Join(methods, " ") != strings.Join(want, " ") {
				t.Errorf("requests: %v, want %v", methods, want)
			}
			if tc.ledger.Legacy {
				// After the handshake every request names the session and
				// the revision agreed on.
				for i, h := range rec.seen[2:] {
					if h.Get("Mcp-Session-Id") == "" || h.Get("Mcp-Protocol-Version") != protocol {
						t.Errorf("request %d: session %q, version %q", i+3, h.Get("Mcp-Session-Id"), h.Get("Mcp-Protocol-Version"))
					}
				}
				return
			}
			// 2026-07-28: no session, and every request names its version
			// and mirrors its method.
			for i, h := range rec.seen {
				if h.Get("Mcp-Session-Id") != "" || h.Get("Mcp-Protocol-Version") != protocol || h.Get("Mcp-Method") != want[i] {
					t.Errorf("request %d: session %q, version %q, method %q", i+1, h.Get("Mcp-Session-Id"), h.Get("Mcp-Protocol-Version"), h.Get("Mcp-Method"))
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
	if !errors.As(err, &se) || !se.Unauthorized() || se.Method != "server/discover" {
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
		if r.Header.Get("Mcp-Method") == "server/discover" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}`)
	}))
	defer srv.Close()
	_, err := mcp.ListTools(context.Background(), srv.URL, nil)
	if err == nil || !strings.Contains(err.Error(), `speaks MCP "2024-11-05"`) {
		t.Errorf("err = %v", err)
	}
}

// modernServer answers server/discover with discover, and initialize and
// tools/list as a server of the earlier revisions would, so a fallback can
// be told apart from a modern listing by the protocol it reports.
func modernServer(t *testing.T, discover func(w http.ResponseWriter, id json.RawMessage), list func(w http.ResponseWriter, id json.RawMessage)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&msg)
		switch msg.Method {
		case "server/discover":
			discover(w, msg.ID)
		case "initialize":
			page(w, msg.ID, `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"old","version":"1"}}`)
		case "tools/list":
			list(w, msg.ID)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestListToolsFromAModernServer(t *testing.T) {
	discovered := func(versions string) func(w http.ResponseWriter, id json.RawMessage) {
		return func(w http.ResponseWriter, id json.RawMessage) {
			page(w, id, `{"resultType":"complete","supportedVersions":`+versions+`,"capabilities":{"tools":{}},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"new","version":"2"},"other":"x"}}`)
		}
	}
	rpcError := func(status int, body string) func(w http.ResponseWriter, id json.RawMessage) {
		return func(w http.ResponseWriter, id json.RawMessage) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":%s}`, id, body)
		}
	}
	oneTool := func(w http.ResponseWriter, id json.RawMessage) {
		page(w, id, `{"resultType":"complete","tools":[{"name":"a"}],"ttlMs":1000,"cacheScope":"public"}`)
	}
	for _, tc := range []struct {
		name     string
		discover func(w http.ResponseWriter, id json.RawMessage)
		list     func(w http.ResponseWriter, id json.RawMessage)
		protocol string // the revision spoken, or "" for an error
		want     string
	}{
		{"modern", discovered(`["2026-07-28","2025-11-25"]`), oneTool, "2026-07-28", ""},
		{"modern without our revision, but an earlier one", discovered(`["2025-06-18"]`), oneTool, "2025-11-25", ""},
		{"only a later revision", rpcError(400, `{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2027-01-01"],"requested":"2026-07-28"}}`),
			oneTool, "", `speaks MCP "2027-01-01"`},
		{"unsupported, but an earlier revision offered", rpcError(400, `{"code":-32022,"message":"Unsupported","data":{"supported":["2025-11-25"]}}`), oneTool, "2025-11-25", ""},
		{"headers refused", rpcError(400, `{"code":-32020,"message":"Header mismatch"}`), oneTool, "", "answered -32020"},
		{"an earlier revision's 400", rpcError(400, `{"code":-32600,"message":"no session"}`), oneTool, "2025-11-25", ""},
		{"an earlier revision's method not found", rpcError(200, `{"code":-32601,"message":"no such method"}`), oneTool, "2025-11-25", ""},
		{"a server error", rpcError(500, `{"code":-32603,"message":"boom"}`), oneTool, "", "500 Internal Server Error"},
		{"a list asking for input", discovered(`["2026-07-28"]`), func(w http.ResponseWriter, id json.RawMessage) {
			page(w, id, `{"resultType":"input_required","inputRequests":{}}`)
		}, "", `asks for more input ("input_required")`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := mcp.ListTools(context.Background(), modernServer(t, tc.discover, tc.list).URL, nil)
			switch {
			case tc.protocol == "":
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("err = %v, want %q", err, tc.want)
				}
			case err != nil:
				t.Errorf("err = %v", err)
			case l.Server.Protocol != tc.protocol || names(l.Tools) != "a":
				t.Errorf("listed %s over %+v", names(l.Tools), l.Server)
			}
		})
	}
}
