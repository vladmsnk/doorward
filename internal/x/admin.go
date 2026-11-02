package x

import (
	"crypto/subtle"
	"net/http"
)

// AdminPrefix is where the Admin API lives.
const AdminPrefix = "/admin/v0"

// AdminRouter serves the Admin API. Each domain package registers its routes
// on it (SetAdminRoutes), and every route registered requires the
// administrator's bearer token; a path no route matches is a plain 404.
type AdminRouter struct {
	mux   *http.ServeMux
	token string
}

// NewAdminRouter returns a router whose routes accept token. An empty token
// refuses every request.
func NewAdminRouter(token string) *AdminRouter {
	return &AdminRouter{mux: http.NewServeMux(), token: token}
}

// HandleFunc registers a route that requires the administrator's token.
func (a *AdminRouter) HandleFunc(pattern string, h http.HandlerFunc) {
	a.mux.HandleFunc(pattern, a.authorized(h))
}

func (a *AdminRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

func (a *AdminRouter) authorized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := BearerToken(r)
		if a.token == "" || !ok || subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="doorward-admin"`)
			WriteError(w, http.StatusUnauthorized, "unauthorized", "an administrator token is required", nil)
			return
		}
		next(w, r)
	}
}

// ErrorResponse is how the Admin API returns a refusal.
type ErrorResponse struct {
	Error    string   `json:"error"`
	Message  string   `json:"message"`
	Problems []string `json:"problems,omitempty"`
}

// WriteError writes an Admin API refusal.
func WriteError(w http.ResponseWriter, status int, code, message string, problems []string) {
	WriteJSON(w, status, ErrorResponse{Error: code, Message: message, Problems: problems})
}

// AdminActor names who made a change. With the bootstrap token that is all
// that is known; administrators who sign in come with C12.
func AdminActor(*http.Request) string { return "admin-token" }
