package configuration

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/x"
	"github.com/vladmsnk/doorward/schema"
)

// Handler serves the Admin API's configuration routes: the documents, the
// status of agents, and the secrets. Every write is validated against the
// contract and against the other documents, under the configuration lock,
// and stored as a new version; nothing is overwritten.
type Handler struct {
	r InternalRegistry
}

// NewHandler returns the configuration handler.
func NewHandler(r InternalRegistry) *Handler { return &Handler{r: r} }

// collections maps URL segments to document kinds.
var collections = map[string]schema.Kind{
	"manifests": schema.Manifest,
	"agents":    schema.Agent,
	"mandates":  schema.Mandate,
}

// SetAdminRoutes registers the routes under /admin/v0/.
func (h *Handler) SetAdminRoutes(a *x.AdminRouter) {
	a.HandleFunc("GET /admin/v0/{collection}", h.list)
	a.HandleFunc("GET /admin/v0/{collection}/{name}", h.get)
	a.HandleFunc("PUT /admin/v0/{collection}/{name}", h.put)
	a.HandleFunc("GET /admin/v0/{collection}/{name}/versions", h.versions)
	a.HandleFunc("GET /admin/v0/{collection}/{name}/versions/{version}", h.version)
	a.HandleFunc("POST /admin/v0/{collection}/{name}/disable", h.setDisabled(true))
	a.HandleFunc("POST /admin/v0/{collection}/{name}/enable", h.setDisabled(false))
	a.HandleFunc("POST /admin/v0/manifests/{name}/draft", h.draftManifest)
	a.HandleFunc("POST /admin/v0/agents/{name}/verify", h.verifyAgent)
	a.HandleFunc("POST /admin/v0/agents/{name}/suspend", h.suspendAgent)
	a.HandleFunc("GET /admin/v0/secrets", h.listSecrets)
	a.HandleFunc("PUT /admin/v0/secrets/{name}", h.putSecret)
	a.HandleFunc("DELETE /admin/v0/secrets/{name}", h.deleteSecret)
}

// Response is how a document is returned: its version envelope and the
// document itself.
type Response struct {
	Kind      string          `json:"kind"`
	Name      string          `json:"name"`
	Version   int             `json:"version"`
	Digest    string          `json:"digest"`
	Disabled  bool            `json:"disabled"`
	CreatedAt time.Time       `json:"created_at"`
	CreatedBy string          `json:"created_by"`
	Document  json.RawMessage `json:"document"`
}

func toResponse(d Document) Response {
	return Response{Kind: d.Kind, Name: d.Name, Version: d.Version, Digest: d.Digest, Disabled: d.Disabled,
		CreatedAt: d.CreatedAt, CreatedBy: d.CreatedBy, Document: d.Doc}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	kind, ok := h.kind(w, r)
	if !ok {
		return
	}
	docs, err := h.r.ConfigurationManager().List(r.Context(), string(kind))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]Response, 0, len(docs))
	for _, d := range docs {
		out = append(out, toResponse(d))
	}
	x.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	kind, ok := h.kind(w, r)
	if !ok {
		return
	}
	d, err := h.r.ConfigurationManager().Current(r.Context(), string(kind), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	x.WriteJSON(w, http.StatusOK, toResponse(d))
}

func (h *Handler) versions(w http.ResponseWriter, r *http.Request) {
	kind, ok := h.kind(w, r)
	if !ok {
		return
	}
	docs, err := h.r.ConfigurationManager().History(r.Context(), string(kind), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]Response, 0, len(docs))
	for _, d := range docs {
		out = append(out, toResponse(d))
	}
	x.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) version(w http.ResponseWriter, r *http.Request) {
	kind, ok := h.kind(w, r)
	if !ok {
		return
	}
	n, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || n < 1 {
		x.WriteError(w, http.StatusBadRequest, "bad_request", "version must be a positive number", nil)
		return
	}
	d, err := h.r.ConfigurationManager().Version(r.Context(), string(kind), r.PathValue("name"), n)
	if err != nil {
		h.fail(w, err)
		return
	}
	x.WriteJSON(w, http.StatusOK, toResponse(d))
}

// put validates the body against the contract, then against the other
// documents, and stores it as the next version.
func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	kind, ok := h.kind(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		x.WriteError(w, http.StatusRequestEntityTooLarge, "too_large", "document is larger than 1 MiB", nil)
		return
	}
	filename := "body.json"
	if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "yaml") {
		filename = "body.yaml"
	}
	srcs, err := schema.Read(filename, body, kind)
	if err != nil {
		x.WriteError(w, http.StatusBadRequest, "invalid_document", err.Error(), nil)
		return
	}
	if len(srcs) != 1 {
		x.WriteError(w, http.StatusBadRequest, "invalid_document", "send exactly one document", nil)
		return
	}
	doc := srcs[0].JSON
	if err := h.r.Validator().Check(kind, doc); err != nil {
		x.WriteError(w, http.StatusBadRequest, "invalid_document", err.Error(), nil)
		return
	}
	var meta struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(doc, &meta)
	if meta.Metadata.Name != name {
		x.WriteError(w, http.StatusBadRequest, "name_mismatch",
			fmt.Sprintf("the URL names %q but metadata.name is %q", name, meta.Metadata.Name), nil)
		return
	}
	var stored Document
	err = change(r.Context(), h.r.ConfigurationLocker(),
		func(after *state, _ Store) error { return after.put(string(kind), doc) },
		func(c Store) (err error) {
			stored, err = c.Documents().Put(r.Context(), string(kind), name, doc, x.AdminActor(r))
			return err
		})
	if err != nil {
		h.fail(w, err)
		return
	}
	h.r.Logger().Info("document stored", "kind", kind, "name", name, "version", stored.Version, "by", stored.CreatedBy)
	x.WriteJSON(w, http.StatusOK, toResponse(stored))
}

func (h *Handler) setDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind, ok := h.kind(w, r)
		if !ok {
			return
		}
		if kind == schema.Agent {
			x.WriteError(w, http.StatusBadRequest, "bad_request", "agents are suspended or verified, not disabled", nil)
			return
		}
		name := r.PathValue("name")
		var d Document
		err := change(r.Context(), h.r.ConfigurationLocker(),
			func(after *state, c Store) error {
				cur, err := c.Documents().Current(r.Context(), string(kind), name)
				if err != nil {
					return err
				}
				if !disabled {
					return after.put(string(kind), cur.Doc)
				}
				if kind == schema.Manifest {
					// A manifest that enabled mandates rest on stays enabled
					// until they no longer name it.
					var m v0.Manifest
					if err := json.Unmarshal(cur.Doc, &m); err != nil {
						return err
					}
					if deps := after.dependents(m.Spec.Audience); len(deps) > 0 {
						return inUse(fmt.Sprintf("manifest %s is named by enabled mandates: %s", name, strings.Join(deps, ", ")))
					}
				}
				after.disable(string(kind), name)
				return nil
			},
			func(c Store) (err error) {
				d, err = c.Documents().SetDisabled(r.Context(), string(kind), name, disabled, x.AdminActor(r))
				return err
			})
		if err != nil {
			h.fail(w, err)
			return
		}
		h.r.Logger().Info("document toggled", "kind", kind, "name", name, "disabled", disabled, "version", d.Version)
		x.WriteJSON(w, http.StatusOK, toResponse(d))
	}
}

// invalidDocument is a document that fails its own schema or rules.
type invalidDocument struct{ err error }

func (e invalidDocument) Error() string { return e.err.Error() }

func (e invalidDocument) Unwrap() error { return e.err }

func (h *Handler) kind(w http.ResponseWriter, r *http.Request) (schema.Kind, bool) {
	kind, ok := collections[r.PathValue("collection")]
	if !ok {
		x.WriteError(w, http.StatusNotFound, "not_found", "collections are manifests, agents and mandates", nil)
	}
	return kind, ok
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, x.ErrNotFound), errors.Is(err, x.ErrConflict):
		x.FailAdmin(w, h.r.Logger(), err)
	case errors.As(err, new(inUse)):
		x.WriteError(w, http.StatusConflict, "in_use", err.Error(), nil)
	case errors.As(err, new(invalidDocument)):
		x.WriteError(w, http.StatusBadRequest, "invalid_document", err.Error(), nil)
	default:
		if p, ok := IsProblems(err); ok {
			x.WriteError(w, http.StatusBadRequest, "rules_violated", "the document contradicts the current configuration", p)
			return
		}
		x.FailAdmin(w, h.r.Logger(), err)
	}
}
