package jwk

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vladmsnk/doorward/internal/x"
)

// WellKnownKeysPath is where the JWK Set is published.
const WellKnownKeysPath = "/.well-known/jwks.json"

// InternalRegistry is what the key handlers need.
type InternalRegistry interface {
	KeyRingProvider
	ManagerProvider
	x.LoggerProvider
	x.ClockProvider
}

// Handler publishes the JWK Set and serves the Admin API's key routes:
// list, rotate, retire.
type Handler struct {
	r InternalRegistry
}

// NewHandler returns the key handler.
func NewHandler(r InternalRegistry) *Handler { return &Handler{r: r} }

// SetPublicRoutes publishes the JWK Set.
func (h *Handler) SetPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+WellKnownKeysPath, h.jwks)
}

// SetAdminRoutes registers the key routes under /admin/v0/keys.
func (h *Handler) SetAdminRoutes(a *x.AdminRouter) {
	a.HandleFunc("GET /admin/v0/keys", h.listKeys)
	a.HandleFunc("POST /admin/v0/keys/rotate", h.rotateKey)
	a.HandleFunc("POST /admin/v0/keys/{kid}/retire", h.retireKey)
}

// jwks publishes every key that is not retired; resource servers may cache
// it for five minutes.
func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	set, err := h.r.KeyRing().JWKS(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(set)
}

// KeyResponse is one signing key as the admin sees it: public part only.
type KeyResponse struct {
	KID       string     `json:"kid"`
	Alg       string     `json:"alg"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

func (h *Handler) listKeys(w http.ResponseWriter, r *http.Request) {
	all, err := h.r.KeyManager().List(r.Context())
	if err != nil {
		x.FailAdmin(w, h.r.Logger(), err)
		return
	}
	active := ""
	if sg := h.r.KeyRing().Signer(); sg != nil {
		active = sg.KID
	}
	out := make([]KeyResponse, 0, len(all))
	for _, k := range all {
		out = append(out, KeyResponse{KID: k.KID, Alg: k.Alg, Active: k.KID == active, CreatedAt: k.CreatedAt, RetiredAt: k.RetiredAt})
	}
	x.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) rotateKey(w http.ResponseWriter, r *http.Request) {
	key, err := h.r.KeyRing().Rotate(r.Context())
	if err != nil {
		x.FailAdmin(w, h.r.Logger(), err)
		return
	}
	h.r.Logger().Info("signing key rotated", "kid", key.Kid, "by", x.AdminActor(r))
	x.WriteJSON(w, http.StatusOK, KeyResponse{KID: key.Kid, Alg: key.Alg, Active: true, CreatedAt: h.r.Now()})
}

func (h *Handler) retireKey(w http.ResponseWriter, r *http.Request) {
	kid := r.PathValue("kid")
	if err := h.r.KeyRing().Retire(r.Context(), kid, h.r.Now()); err != nil {
		if errors.Is(err, x.ErrNotFound) {
			x.FailAdmin(w, h.r.Logger(), err)
			return
		}
		x.WriteError(w, http.StatusConflict, "active_key", err.Error(), nil)
		return
	}
	h.r.Logger().Info("signing key retired", "kid", kid, "by", x.AdminActor(r))
	w.WriteHeader(http.StatusNoContent)
}
