// Command demo-ledger runs the demo MCP server doorward's gateway is tried
// against. It wants the API key in DEMO_LEDGER_API_KEY (default
// lk_live_example, the value the examples store as ledger-mcp-api-key).
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/vladmsnk/doorward/internal/demoledger"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "address to listen on")
	sse := flag.Bool("sse", false, "answer as event streams instead of plain JSON")
	pageSize := flag.Int("page-size", 0, "list this many tools a page (default: all on one)")
	legacy := flag.Bool("legacy", false, "speak only the revisions before 2026-07-28, through the handshake")
	flag.Parse()
	key := os.Getenv("DEMO_LEDGER_API_KEY")
	if key == "" {
		key = "lk_live_example"
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	srv := &http.Server{
		Addr: *addr, Handler: &demoledger.Server{APIKey: key, SSE: *sse, PageSize: *pageSize, Legacy: *legacy, Log: log},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("demo-ledger serving", "addr", *addr, "endpoint", "/mcp", "sse", *sse)
	mux := http.NewServeMux()
	mux.Handle("/mcp", srv.Handler)
	srv.Handler = mux
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
