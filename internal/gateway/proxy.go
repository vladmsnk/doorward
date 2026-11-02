package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/vladmsnk/doorward/internal/configuration"
)

// rewrite is what the proxy does to one forwarded POST: the body to send,
// and for tools/list, the tools to keep.
type rewrite struct {
	body   []byte
	id     json.RawMessage
	filter func(tool string) bool
}

// proxy forwards the request to the manifest's upstream with the server's
// credential, and streams the answer back, rewriting a tool list on the
// way when asked.
func (h *Handler) proxy(w http.ResponseWriter, r *http.Request, snap *configuration.Snapshot, man configuration.Manifest, rw *rewrite) {
	target, err := url.Parse(man.Spec.Upstream.URL)
	if err != nil {
		http.Error(w, "the manifest's upstream URL is invalid", http.StatusBadGateway)
		return
	}
	header, value, err := h.credential(r.Context(), snap, man)
	if err != nil {
		h.r.Logger().Error("gateway: upstream credential", "manifest", man.Metadata.Name, "err", err)
		http.Error(w, "the gateway cannot read the upstream credential", http.StatusBadGateway)
		return
	}
	rp := &httputil.ReverseProxy{
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = target
			pr.Out.Host = target.Host
			// Forward only the protocol's own transport and tracing
			// headers, never the client's. The agent's grant, cookies and
			// anything a server might mistake for an identity signal (an
			// X-Forwarded-* header, say) are dropped; the upstream
			// credential is set in their place.
			pr.Out.Header = forwardHeaders(pr.In.Header)
			if header != "" {
				pr.Out.Header.Set(header, value)
			}
			if rw != nil && rw.body != nil {
				pr.Out.Body = io.NopCloser(bytes.NewReader(rw.body))
				pr.Out.ContentLength = int64(len(rw.body))
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.r.Logger().Error("gateway: upstream", "manifest", man.Metadata.Name, "err", err)
			http.Error(w, "the server behind the gateway did not answer", http.StatusBadGateway)
		},
	}
	if rw != nil && rw.filter != nil {
		rp.ModifyResponse = func(res *http.Response) error { return filterTools(res, rw) }
	}
	rp.ServeHTTP(w, r)
}

// credential returns the header the upstream wants, opened from the secret
// store; cached per configuration version, that of the request's snapshot.
func (h *Handler) credential(ctx context.Context, snap *configuration.Snapshot, man configuration.Manifest) (string, string, error) {
	auth := man.Spec.Upstream.Auth
	if auth == nil {
		return "", "", nil
	}
	version := snap.Version
	h.mu.Lock()
	if h.ckVers != version {
		h.creds, h.ckVers = map[string]cachedCred{}, version
	}
	c, ok := h.creds[auth.SecretRef]
	h.mu.Unlock()
	if ok {
		return c.header, c.value, nil
	}
	sealed, err := h.r.SecretManager().Get(ctx, auth.SecretRef)
	if err != nil {
		return "", "", fmt.Errorf("secret %s: %w", auth.SecretRef, err)
	}
	plain, err := h.r.Sealer().Open(sealed, configuration.SecretPurpose(auth.SecretRef))
	if err != nil {
		return "", "", fmt.Errorf("secret %s: %w", auth.SecretRef, err)
	}
	c = cachedCred{header: auth.Header, value: auth.Prefix + string(plain)}
	h.mu.Lock()
	h.creds[auth.SecretRef] = c
	h.mu.Unlock()
	return c.header, c.value, nil
}

// forwardHeaders keeps only the headers the MCP transport defines and the
// tracing headers, dropping everything else the client sent. The upstream
// credential is added by the caller.
func forwardHeaders(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for name, values := range in {
		if ck := http.CanonicalHeaderKey(name); forwardable(ck) {
			out[ck] = values
		}
	}
	return out
}

func forwardable(canonical string) bool {
	switch canonical {
	case "Accept", "Content-Type", "Traceparent", "Tracestate", "Baggage", "Last-Event-Id":
		return true
	default:
		// MCP-Protocol-Version, Mcp-Session-Id, Mcp-Method, Mcp-Name and
		// the Mcp-Param-* request-metadata headers.
		return strings.HasPrefix(canonical, "Mcp-")
	}
}
