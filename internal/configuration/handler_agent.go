package configuration

import (
	"encoding/json"
	"net/http"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/x"
	"github.com/vladmsnk/doorward/schema"
)

// verifyAgent marks an agent verified and names its owner, as a new
// version of the agent document.
func (h *Handler) verifyAgent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Owner v0.Owner `json:"owner"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Owner.Team == "" {
		x.WriteError(w, http.StatusBadRequest, "bad_request", `send {"owner": {"team": "...", "contact": "..."}}`, nil)
		return
	}
	h.changeAgent(w, r, func(a *v0.Agent) {
		a.Spec.Status = v0.AgentVerified
		a.Spec.Owner = &body.Owner
	})
}

// suspendAgent marks an agent suspended and revokes its live grants.
func (h *Handler) suspendAgent(w http.ResponseWriter, r *http.Request) {
	h.changeAgent(w, r, func(a *v0.Agent) { a.Spec.Status = v0.AgentSuspended })
	if revoked, err := h.r.GrantRevoker().RevokeByAgent(r.Context(), r.PathValue("name"), h.r.Now()); err != nil {
		h.r.Logger().Error("revoking grants after suspension", "agent", r.PathValue("name"), "err", err)
	} else if len(revoked) > 0 {
		h.r.Logger().Info("grants revoked", "agent", r.PathValue("name"), "count", len(revoked))
	}
}

func (h *Handler) changeAgent(w http.ResponseWriter, r *http.Request, edit func(*v0.Agent)) {
	name := r.PathValue("name")
	var doc []byte
	var status v0.AgentStatus
	var stored Document
	err := change(r.Context(), h.r.ConfigurationLocker(),
		func(after *state, c Store) error {
			cur, err := c.Documents().Current(r.Context(), v0.KindAgent, name)
			if err != nil {
				return err
			}
			var a v0.Agent
			if err := json.Unmarshal(cur.Doc, &a); err != nil {
				return err
			}
			edit(&a)
			status = a.Spec.Status
			if doc, err = json.Marshal(a); err != nil {
				return err
			}
			// The changed document goes through the same door as a
			// written one.
			if err := h.r.Validator().Check(schema.Agent, doc); err != nil {
				return invalidDocument{err}
			}
			return after.put(v0.KindAgent, doc)
		},
		func(c Store) (err error) {
			stored, err = c.Documents().Put(r.Context(), v0.KindAgent, name, doc, x.AdminActor(r))
			return err
		})
	if err != nil {
		h.fail(w, err)
		return
	}
	h.r.Logger().Info("agent status changed", "agent", name, "status", status, "version", stored.Version, "by", stored.CreatedBy)
	x.WriteJSON(w, http.StatusOK, toResponse(stored))
}
