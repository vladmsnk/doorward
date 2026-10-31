// Package admin is the Admin API: the one way configuration gets into the
// box. It validates every write against the contract and the rules between
// documents, stores it as a new version, and never overwrites.
package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/keys"
	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/store"
	"github.com/vladmsnk/doorward/schema"
)

// Server serves the Admin API.
type Server struct {
	Store     store.Store
	Validator *schema.Validator
	// Token is the bootstrap bearer token. Requests without it are refused.
	Token string
	// Sealer seals secret values before they reach the store.
	Sealer *sealer.Sealer
	// Keys manages the signing keys; nil disables the key routes.
	Keys *keys.Manager
	Log  *slog.Logger
	Now  func() time.Time
}

// collections maps URL segments to document kinds.
var collections = map[string]schema.Kind{
	"manifests": schema.Manifest,
	"agents":    schema.Agent,
	"mandates":  schema.Mandate,
}

// Handler returns the API's routes, all under /admin/v0/.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v0/{collection}", s.auth(s.list))
	mux.HandleFunc("GET /admin/v0/{collection}/{name}", s.auth(s.get))
	mux.HandleFunc("PUT /admin/v0/{collection}/{name}", s.auth(s.put))
	mux.HandleFunc("GET /admin/v0/{collection}/{name}/versions", s.auth(s.versions))
	mux.HandleFunc("GET /admin/v0/{collection}/{name}/versions/{version}", s.auth(s.version))
	mux.HandleFunc("POST /admin/v0/{collection}/{name}/disable", s.auth(s.setDisabled(true)))
	mux.HandleFunc("POST /admin/v0/{collection}/{name}/enable", s.auth(s.setDisabled(false)))
	mux.HandleFunc("POST /admin/v0/agents/{name}/verify", s.auth(s.verifyAgent))
	mux.HandleFunc("POST /admin/v0/agents/{name}/suspend", s.auth(s.suspendAgent))
	mux.HandleFunc("GET /admin/v0/secrets", s.auth(s.listSecrets))
	mux.HandleFunc("PUT /admin/v0/secrets/{name}", s.auth(s.putSecret))
	mux.HandleFunc("DELETE /admin/v0/secrets/{name}", s.auth(s.deleteSecret))
	mux.HandleFunc("GET /admin/v0/keys", s.auth(s.listKeys))
	mux.HandleFunc("POST /admin/v0/keys/rotate", s.auth(s.rotateKey))
	mux.HandleFunc("POST /admin/v0/keys/{kid}/retire", s.auth(s.retireKey))
	return mux
}

// SecretPurpose is the sealing purpose of a secret: bound to its name, so
// one secret's ciphertext cannot be moved under another name.
func SecretPurpose(name string) string { return "secret:" + name }

// ---------------------------------------------------------------- secrets

// SecretResponse is what is said about a secret: everything but its value.
type SecretResponse struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.Secrets().List(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]SecretResponse, 0, len(list))
	for _, i := range list {
		out = append(out, SecretResponse{Name: i.Name, CreatedAt: i.CreatedAt, UpdatedAt: i.UpdatedAt, UpdatedBy: i.UpdatedBy})
	}
	writeJSON(w, http.StatusOK, out)
}

// putSecret stores a value. The body is {"value": "..."}; the value is
// never returned by any route.
func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nameRE.MatchString(name) {
		writeError(w, http.StatusBadRequest, "bad_request", "a secret name is lower case letters, digits, '.', '_' and '-'", nil)
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Value == "" {
		writeError(w, http.StatusBadRequest, "bad_request", `send {"value": "..."}`, nil)
		return
	}
	sealed, err := s.Sealer.Seal([]byte(body.Value), SecretPurpose(name))
	if err != nil {
		s.fail(w, err)
		return
	}
	err = s.change(r.Context(),
		func(after *snapshot, _ store.Config) error { after.secrets[name] = true; return nil },
		func(c store.Config) error { return c.Secrets().Put(r.Context(), name, sealed, s.actor(r)) })
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Log.Info("secret stored", "name", name, "by", s.actor(r))
	w.WriteHeader(http.StatusNoContent)
}

// deleteSecret removes a secret unless an enabled manifest still names it.
func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := s.change(r.Context(),
		func(after *snapshot, _ store.Config) error {
			if users := after.secretUsers(name); len(users) > 0 {
				return inUse(fmt.Sprintf("secret %s is named by enabled manifests: %s", name, strings.Join(users, ", ")))
			}
			delete(after.secrets, name)
			return nil
		},
		func(c store.Config) error { return c.Secrets().Delete(r.Context(), name) })
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Log.Info("secret deleted", "name", name, "by", s.actor(r))
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- keys

// KeyResponse is one signing key as the admin sees it: public part only.
type KeyResponse struct {
	KID       string     `json:"kid"`
	Alg       string     `json:"alg"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	all, err := s.Store.Keys().List(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	active := ""
	if sg := s.Keys.Signer(); sg != nil {
		active = sg.KID
	}
	out := make([]KeyResponse, 0, len(all))
	for _, k := range all {
		out = append(out, KeyResponse{KID: k.KID, Alg: k.Alg, Active: k.KID == active, CreatedAt: k.CreatedAt, RetiredAt: k.RetiredAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) rotateKey(w http.ResponseWriter, r *http.Request) {
	jwk, err := s.Keys.Rotate(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Log.Info("signing key rotated", "kid", jwk.Kid, "by", s.actor(r))
	writeJSON(w, http.StatusOK, KeyResponse{KID: jwk.Kid, Alg: jwk.Alg, Active: true, CreatedAt: s.now()})
}

func (s *Server) retireKey(w http.ResponseWriter, r *http.Request) {
	kid := r.PathValue("kid")
	if err := s.Keys.Retire(r.Context(), kid, s.now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, err)
			return
		}
		writeError(w, http.StatusConflict, "active_key", err.Error(), nil)
		return
	}
	s.Log.Info("signing key retired", "kid", kid, "by", s.actor(r))
	w.WriteHeader(http.StatusNoContent)
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

// ErrorResponse is how a refusal is returned.
type ErrorResponse struct {
	Error    string   `json:"error"`
	Message  string   `json:"message"`
	Problems []string `json:"problems,omitempty"`
}

func toResponse(d store.Document) Response {
	return Response{Kind: d.Kind, Name: d.Name, Version: d.Version, Digest: d.Digest, Disabled: d.Disabled,
		CreatedAt: d.CreatedAt, CreatedBy: d.CreatedBy, Document: d.Doc}
}

// ---------------------------------------------------------------- handlers

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	kind, ok := s.kind(w, r)
	if !ok {
		return
	}
	docs, err := s.Store.Documents().List(r.Context(), string(kind))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]Response, 0, len(docs))
	for _, d := range docs {
		out = append(out, toResponse(d))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	kind, ok := s.kind(w, r)
	if !ok {
		return
	}
	d, err := s.Store.Documents().Current(r.Context(), string(kind), r.PathValue("name"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toResponse(d))
}

func (s *Server) versions(w http.ResponseWriter, r *http.Request) {
	kind, ok := s.kind(w, r)
	if !ok {
		return
	}
	docs, err := s.Store.Documents().History(r.Context(), string(kind), r.PathValue("name"))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]Response, 0, len(docs))
	for _, d := range docs {
		out = append(out, toResponse(d))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	kind, ok := s.kind(w, r)
	if !ok {
		return
	}
	n, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || n < 1 {
		writeError(w, http.StatusBadRequest, "bad_request", "version must be a positive number", nil)
		return
	}
	d, err := s.Store.Documents().Version(r.Context(), string(kind), r.PathValue("name"), n)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toResponse(d))
}

// put validates the body against the contract, then against the other
// documents, and stores it as the next version.
func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	kind, ok := s.kind(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "document is larger than 1 MiB", nil)
		return
	}
	filename := "body.json"
	if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "yaml") {
		filename = "body.yaml"
	}
	srcs, err := schema.Read(filename, body, kind)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_document", err.Error(), nil)
		return
	}
	if len(srcs) != 1 {
		writeError(w, http.StatusBadRequest, "invalid_document", "send exactly one document", nil)
		return
	}
	doc := srcs[0].JSON
	if err := s.Validator.Check(kind, doc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_document", err.Error(), nil)
		return
	}
	var meta struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(doc, &meta)
	if meta.Metadata.Name != name {
		writeError(w, http.StatusBadRequest, "name_mismatch",
			fmt.Sprintf("the URL names %q but metadata.name is %q", name, meta.Metadata.Name), nil)
		return
	}
	var stored store.Document
	err = s.change(r.Context(),
		func(after *snapshot, _ store.Config) error { return after.put(string(kind), doc) },
		func(c store.Config) (err error) {
			stored, err = c.Documents().Put(r.Context(), string(kind), name, doc, s.actor(r))
			return err
		})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Log.Info("document stored", "kind", kind, "name", name, "version", stored.Version, "by", stored.CreatedBy)
	writeJSON(w, http.StatusOK, toResponse(stored))
}

// change makes one configuration change under the configuration lock. It
// loads the configuration as the last change left it, lets try apply the
// change to a copy, refuses the change if the copy breaks a rule the
// original did not, and otherwise lets commit write it. Nothing is written
// unless the whole change is accepted.
func (s *Server) change(ctx context.Context, try func(after *snapshot, c store.Config) error, commit func(c store.Config) error) error {
	return s.Store.LockConfig(ctx, func(c store.Config) error {
		before, err := load(ctx, c)
		if err != nil {
			return err
		}
		after := before.clone()
		if err := try(after, c); err != nil {
			return err
		}
		if p := introduced(before, after); len(p) > 0 {
			return p
		}
		return commit(c)
	})
}

func (s *Server) setDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind, ok := s.kind(w, r)
		if !ok {
			return
		}
		if kind == schema.Agent {
			writeError(w, http.StatusBadRequest, "bad_request", "agents are suspended or verified, not disabled", nil)
			return
		}
		name := r.PathValue("name")
		var d store.Document
		err := s.change(r.Context(),
			func(after *snapshot, c store.Config) error {
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
			func(c store.Config) (err error) {
				d, err = c.Documents().SetDisabled(r.Context(), string(kind), name, disabled, s.actor(r))
				return err
			})
		if err != nil {
			s.fail(w, err)
			return
		}
		s.Log.Info("document toggled", "kind", kind, "name", name, "disabled", disabled, "version", d.Version)
		writeJSON(w, http.StatusOK, toResponse(d))
	}
}

// verifyAgent marks an agent verified and names its owner, as a new
// version of the agent document.
func (s *Server) verifyAgent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Owner v0.Owner `json:"owner"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Owner.Team == "" {
		writeError(w, http.StatusBadRequest, "bad_request", `send {"owner": {"team": "...", "contact": "..."}}`, nil)
		return
	}
	s.changeAgent(w, r, func(a *v0.Agent) {
		a.Spec.Status = v0.AgentVerified
		a.Spec.Owner = &body.Owner
	})
}

// suspendAgent marks an agent suspended and revokes its live grants.
func (s *Server) suspendAgent(w http.ResponseWriter, r *http.Request) {
	s.changeAgent(w, r, func(a *v0.Agent) { a.Spec.Status = v0.AgentSuspended })
	if revoked, err := s.Store.Grants().RevokeByAgent(r.Context(), r.PathValue("name"), s.now()); err != nil {
		s.Log.Error("revoking grants after suspension", "agent", r.PathValue("name"), "err", err)
	} else if len(revoked) > 0 {
		s.Log.Info("grants revoked", "agent", r.PathValue("name"), "count", len(revoked))
	}
}

func (s *Server) changeAgent(w http.ResponseWriter, r *http.Request, change func(*v0.Agent)) {
	name := r.PathValue("name")
	var doc []byte
	var status v0.AgentStatus
	var stored store.Document
	err := s.change(r.Context(),
		func(after *snapshot, c store.Config) error {
			cur, err := c.Documents().Current(r.Context(), v0.KindAgent, name)
			if err != nil {
				return err
			}
			var a v0.Agent
			if err := json.Unmarshal(cur.Doc, &a); err != nil {
				return err
			}
			change(&a)
			status = a.Spec.Status
			if doc, err = json.Marshal(a); err != nil {
				return err
			}
			// The changed document goes through the same door as a
			// written one.
			if err := s.Validator.Check(schema.Agent, doc); err != nil {
				return invalidDocument{err}
			}
			return after.put(v0.KindAgent, doc)
		},
		func(c store.Config) (err error) {
			stored, err = c.Documents().Put(r.Context(), v0.KindAgent, name, doc, s.actor(r))
			return err
		})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Log.Info("agent status changed", "agent", name, "status", status, "version", stored.Version, "by", stored.CreatedBy)
	writeJSON(w, http.StatusOK, toResponse(stored))
}

// invalidDocument is a document that fails its own schema or rules.
type invalidDocument struct{ err error }

func (e invalidDocument) Error() string { return e.err.Error() }
func (e invalidDocument) Unwrap() error { return e.err }

// ---------------------------------------------------------------- plumbing

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.Token == "" || !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="doorward-admin"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "an administrator token is required", nil)
			return
		}
		next(w, r)
	}
}

// actor names who made a change. With the bootstrap token that is all we
// know; identity-provider administrators arrive with the consent work.
func (s *Server) actor(*http.Request) string { return "admin-token" }

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) kind(w http.ResponseWriter, r *http.Request) (schema.Kind, bool) {
	kind, ok := collections[r.PathValue("collection")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "collections are manifests, agents and mandates", nil)
	}
	return kind, ok
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such document", nil)
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", err.Error(), nil)
	case errors.As(err, new(inUse)):
		writeError(w, http.StatusConflict, "in_use", err.Error(), nil)
	case errors.As(err, new(invalidDocument)):
		writeError(w, http.StatusBadRequest, "invalid_document", err.Error(), nil)
	default:
		if p, ok := IsProblems(err); ok {
			writeError(w, http.StatusBadRequest, "rules_violated", "the document contradicts the current configuration", p)
			return
		}
		s.Log.Error("admin request failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error", nil)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string, problems []string) {
	writeJSON(w, status, ErrorResponse{Error: code, Message: message, Problems: problems})
}
