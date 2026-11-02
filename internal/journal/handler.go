package journal

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/vladmsnk/doorward/internal/x"
)

// InternalRegistry is what the journal handler needs.
type InternalRegistry interface {
	ManagerProvider
	x.LoggerProvider
}

// Handler serves the Admin API's journal export.
type Handler struct {
	r InternalRegistry
}

// NewHandler returns the journal handler.
func NewHandler(r InternalRegistry) *Handler { return &Handler{r: r} }

// SetAdminRoutes registers GET /admin/v0/decisions.
func (h *Handler) SetAdminRoutes(a *x.AdminRouter) {
	a.HandleFunc("GET /admin/v0/decisions", h.exportDecisions)
}

// exportDecisions writes decision records as JSON lines, from ?from=SEQ
// (default 0), at most ?limit=N of them (default and cap 10000), oldest
// first, for an external verifier or an archive.
func (h *Handler) exportDecisions(w http.ResponseWriter, r *http.Request) {
	from, limit := uint64(0), uint64(10000)
	for _, q := range []struct {
		name string
		dst  *uint64
	}{{"from", &from}, {"limit", &limit}} {
		name, dst := q.name, q.dst
		if v := r.URL.Query().Get(name); v != "" {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				x.WriteError(w, http.StatusBadRequest, "bad_request", name+" must be a non-negative integer", nil)
				return
			}
			*dst = n
		}
	}
	if limit == 0 || limit > 10000 {
		limit = 10000
	}
	records, err := h.r.JournalManager().Range(r.Context(), from, from+limit)
	if err != nil {
		x.FailAdmin(w, h.r.Logger(), err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	for _, d := range records {
		line, err := json.Marshal(d)
		if err != nil {
			h.r.Logger().Error("exporting a decision", "decision", d.ID, "err", err)
			return
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			return
		}
	}
}
