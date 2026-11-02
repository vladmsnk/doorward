package x

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// WriteJSON writes v as a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// BearerToken returns the token of an Authorization: Bearer header, and
// false when there is none or it is empty.
func BearerToken(r *http.Request) (string, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return token, ok && token != ""
}

var traceparent = regexp.MustCompile(`^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$`)

// TraceParent returns the trace ID of a W3C traceparent header, and false
// when there is none, it is malformed, or its trace ID is all zeros.
func TraceParent(r *http.Request) (string, bool) {
	m := traceparent.FindStringSubmatch(r.Header.Get("traceparent"))
	if m == nil || m[1] == strings.Repeat("0", 32) {
		return "", false
	}
	return m[1], true
}

// NewTraceID starts a trace: 16 random bytes in hex.
func NewTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NameRE is what names of documents, secrets and points of enforcement
// look like: lower case letters, digits, '.', '_' and '-', at most 64.
var NameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
