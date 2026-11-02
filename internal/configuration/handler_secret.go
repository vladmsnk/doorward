package configuration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vladmsnk/doorward/internal/x"
)

// SecretResponse is what is said about a secret: everything but its value.
type SecretResponse struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

func (h *Handler) listSecrets(w http.ResponseWriter, r *http.Request) {
	list, err := h.r.SecretManager().List(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]SecretResponse, 0, len(list))
	for _, i := range list {
		out = append(out, SecretResponse(i))
	}
	x.WriteJSON(w, http.StatusOK, out)
}

// putSecret stores a value. The body is {"value": "..."}; the value is
// never returned by any route.
func (h *Handler) putSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !x.NameRE.MatchString(name) {
		x.WriteError(w, http.StatusBadRequest, "bad_request", "a secret name is lower case letters, digits, '.', '_' and '-'", nil)
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Value == "" {
		x.WriteError(w, http.StatusBadRequest, "bad_request", `send {"value": "..."}`, nil)
		return
	}
	sealed, err := h.r.Sealer().Seal([]byte(body.Value), SecretPurpose(name))
	if err != nil {
		h.fail(w, err)
		return
	}
	err = change(r.Context(), h.r.ConfigurationLocker(),
		func(after *state, _ Store) error { after.secrets[name] = true; return nil },
		func(c Store) error { return c.Secrets().Put(r.Context(), name, sealed, x.AdminActor(r)) })
	if err != nil {
		h.fail(w, err)
		return
	}
	h.r.Logger().Info("secret stored", "name", name, "by", x.AdminActor(r))
	w.WriteHeader(http.StatusNoContent)
}

// deleteSecret removes a secret unless an enabled manifest still names it.
func (h *Handler) deleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := change(r.Context(), h.r.ConfigurationLocker(),
		func(after *state, _ Store) error {
			if users := after.secretUsers(name); len(users) > 0 {
				return inUse(fmt.Sprintf("secret %s is named by enabled manifests: %s", name, strings.Join(users, ", ")))
			}
			delete(after.secrets, name)
			return nil
		},
		func(c Store) error { return c.Secrets().Delete(r.Context(), name) })
	if err != nil {
		h.fail(w, err)
		return
	}
	h.r.Logger().Info("secret deleted", "name", name, "by", x.AdminActor(r))
	w.WriteHeader(http.StatusNoContent)
}
