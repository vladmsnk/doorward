package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/mcp"
	"github.com/vladmsnk/doorward/internal/x"
	"github.com/vladmsnk/doorward/schema"
)

// draftTimeout is how long a draft waits for the manifest's server.
const draftTimeout = 20 * time.Second

// DraftResponse is a stored manifest drafted again from its server's
// tools: who listed them, the version the draft was merged into, and the
// draft with its changes and notes.
type DraftResponse struct {
	Server  mcp.Server `json:"server"`
	Version int        `json:"version"`
	Digest  string     `json:"digest"`
	Draft
}

// draftManifest drafts a stored MCP manifest again from its server's tool
// list, as doorward import mcp --against does, with the stored secret as
// the credential. It stores nothing: the draft is PUT by whoever has
// reviewed it. The body may name tools to leave out: {"skip": [...]}.
func (h *Handler) draftManifest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Skip []string `json:"skip"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err == nil && len(body) > 0 {
		err = json.Unmarshal(body, &req)
	}
	if err != nil {
		x.WriteError(w, http.StatusBadRequest, "bad_request", `send nothing, or {"skip": ["tool", ...]}`, nil)
		return
	}
	name := r.PathValue("name")
	cur, err := h.r.ConfigurationManager().Current(r.Context(), v0.KindManifest, name)
	if err != nil {
		h.fail(w, err)
		return
	}
	m, err := schema.Decode[v0.Manifest](h.r.Validator(), cur.Doc)
	if err != nil {
		h.fail(w, fmt.Errorf("manifest %s: %w", name, err))
		return
	}
	if m.Spec.Protocol != v0.ProtocolMCP {
		x.WriteError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("manifest %s is an HTTP manifest; only MCP servers list their tools", name), nil)
		return
	}
	header := http.Header{}
	if auth := m.Spec.Upstream.Auth; auth != nil {
		plain, err := OpenSecret(r.Context(), h.r.SecretManager(), h.r.Sealer(), auth.SecretRef)
		if errors.Is(err, x.ErrNotFound) {
			x.WriteError(w, http.StatusConflict, "conflict", fmt.Sprintf("manifest %s names secret %s, which is not stored", name, auth.SecretRef), nil)
			return
		}
		if err != nil {
			h.fail(w, err)
			return
		}
		header.Set(auth.Header, auth.Prefix+string(plain))
	}

	ctx, cancel := context.WithTimeout(r.Context(), draftTimeout)
	defer cancel()
	listing, err := mcp.ListTools(ctx, m.Spec.Upstream.URL, header)
	if err != nil {
		x.WriteError(w, http.StatusBadGateway, "upstream_failed", err.Error(), nil)
		return
	}
	d := DraftManifest(m, listing.Tools, req.Skip)
	doc, err := json.Marshal(d.Manifest)
	if err != nil {
		h.fail(w, err)
		return
	}
	if err := h.r.Validator().Check(schema.Manifest, doc); err != nil {
		x.WriteError(w, http.StatusBadGateway, "invalid_draft", "the server's tools do not make a valid manifest: "+err.Error(), nil)
		return
	}
	h.r.Logger().Info("manifest drafted", "name", name, "version", cur.Version, "changes", len(d.Changes))
	x.WriteJSON(w, http.StatusOK, DraftResponse{Server: listing.Server, Version: cur.Version, Digest: cur.Digest, Draft: d})
}
