// Package mcp is the client side of the Model Context Protocol over
// Streamable HTTP, as much of it as reading a server's tools takes:
// server/discover, or for a server of an earlier revision the initialize
// handshake, then tools/list page by page. Package gateway is the server
// side.
//
// Everything a server sends is its own say-so: the names, the descriptions,
// the schemas and above all the annotations. The client bounds how much it
// reads and how long it waits, and leaves judging the tools to the caller.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vladmsnk/doorward/internal/x"
)

// ProtocolVersion is the revision the client asks for first: every request
// carries it, and there is no handshake.
const ProtocolVersion = "2026-07-28"

// legacy are the earlier revisions the client also reads, newest first,
// spoken through the initialize handshake.
var legacy = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// versions are all the revisions the client reads, newest first.
var versions = append([]string{ProtocolVersion}, legacy...)

// Keys a 2026-07-28 request names itself under in its params' _meta.
const (
	metaVersion      = "io.modelcontextprotocol/protocolVersion"
	metaClientInfo   = "io.modelcontextprotocol/clientInfo"
	metaCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo   = "io.modelcontextprotocol/serverInfo"
)

// JSON-RPC errors only a server of 2026-07-28 or later answers with.
const (
	codeHeaderMismatch     = -32020
	codeMissingCapability  = -32021
	codeUnsupportedVersion = -32022
)

var clientInfo = map[string]any{"name": "doorward", "version": "import"}

// Bounds on what a server may send.
const (
	// MaxMessage bounds one response, a JSON body or a whole event stream.
	MaxMessage = 4 << 20
	// MaxPages bounds how many pages a tool list may run to.
	MaxPages = 100
	// MaxTools bounds how many tools a server may list.
	MaxTools = 1000
)

// Tool is one tool as the server lists it.
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	Annotations *Annotations    `json:"annotations,omitempty"`
}

// Annotations are a tool's hints about how it behaves. The protocol calls
// them untrusted unless they come from a trusted server; a hint that is
// absent is nil, so that it can be told apart from one set to false.
type Annotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// Server is who answered the handshake, and in which revision.
type Server struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Protocol string `json:"protocol"`
}

// Listing is a server's tools, in the order it lists them.
type Listing struct {
	Server Server
	Tools  []Tool
}

// StatusError is an HTTP answer other than success.
type StatusError struct {
	Method string
	Code   int
	Status string
	// Body is the start of the answer, cleaned for printing.
	Body string
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("%s: the server answered %s", e.Method, e.Status)
	if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

// Unauthorized reports whether the server refused the credential.
func (e *StatusError) Unauthorized() bool {
	return e.Code == http.StatusUnauthorized || e.Code == http.StatusForbidden
}

// client refuses redirects: following one would carry the server's
// credential to wherever the redirect points.
var client = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// ListTools connects to the MCP server at url and reads every page of its
// tool list: in revision 2026-07-28 when the server speaks it, otherwise
// through the handshake of the earlier revisions. header goes with every
// request, for the server's credential. ctx bounds the whole exchange.
func ListTools(ctx context.Context, url string, header http.Header) (Listing, error) {
	s := &session{url: url, header: header}
	defer s.close(ctx)
	server, modern, err := s.discover(ctx)
	if err != nil {
		return Listing{}, err
	}
	if !modern {
		s.modern, s.version = false, ""
		if server, err = s.initialize(ctx); err != nil {
			return Listing{}, err
		}
	}
	tools, err := s.listTools(ctx)
	if err != nil {
		return Listing{}, err
	}
	return Listing{Server: server, Tools: tools}, nil
}

// session is one conversation with a server.
type session struct {
	url    string
	header http.Header
	// modern: the server speaks 2026-07-28, so every request names its
	// version and mirrors its method in a header, and there is no session.
	modern bool
	// id is the MCP-Session-Id the server gave, if any; version is the
	// revision agreed on. Both go with every request after the handshake.
	id, version string
	lastID      int
}

// discover asks the server who it is in revision 2026-07-28, and reports
// false, without an error, for a server of an earlier revision, to be
// spoken to through the handshake. As the revision's backward
// compatibility describes, a 4xx answer that is not a modern JSON-RPC
// error, or a JSON-RPC error that is not one, marks an earlier revision; a
// modern error is answered, never fallen back from. A refused credential,
// a redirect or a server error ends the import whatever the revision.
func (s *session) discover(ctx context.Context) (Server, bool, error) {
	s.modern, s.version = true, ProtocolVersion
	s.lastID++
	id := strconv.Itoa(s.lastID)
	res, err := s.post(ctx, "server/discover", s.message("server/discover", s.lastID, nil))
	if err != nil {
		return Server{}, false, err
	}
	defer func() { _ = res.Body.Close() }()
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden,
		res.StatusCode/100 == 3, res.StatusCode/100 == 5:
		return Server{}, false, statusError("server/discover", res)
	case res.StatusCode != http.StatusOK && res.StatusCode != http.StatusBadRequest:
		return Server{}, false, nil
	}
	reply, err := readResponse(res, id)
	if err != nil {
		if res.StatusCode == http.StatusBadRequest {
			return Server{}, false, nil
		}
		return Server{}, false, fmt.Errorf("server/discover: %w", err)
	}
	if e := reply.Error; e != nil {
		switch e.Code {
		case codeUnsupportedVersion:
			var data struct {
				Supported []string `json:"supported"`
			}
			_ = json.Unmarshal(e.Data, &data)
			return Server{}, false, unsupported(data.Supported)
		case codeHeaderMismatch, codeMissingCapability:
			return Server{}, false, fmt.Errorf("server/discover: the server answered %d %s", e.Code, strconv.Quote(clean(e.Message, 200)))
		}
		return Server{}, false, nil
	}
	var result struct {
		SupportedVersions []string                   `json:"supportedVersions"`
		Meta              map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(reply.Result, &result); err != nil {
		return Server{}, false, fmt.Errorf("server/discover: the result is not a discovery: %w", err)
	}
	if !slices.Contains(result.SupportedVersions, ProtocolVersion) {
		return Server{}, false, unsupported(result.SupportedVersions)
	}
	var info struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	_ = json.Unmarshal(result.Meta[metaServerInfo], &info)
	return Server{Name: clean(info.Name, 128), Version: clean(info.Version, 64), Protocol: ProtocolVersion}, true, nil
}

// unsupported is nil when a modern server also offers an earlier revision
// the client reads, which the handshake then speaks, and otherwise says
// what the server speaks.
func unsupported(supported []string) error {
	for _, v := range supported {
		if slices.Contains(legacy, v) {
			return nil
		}
	}
	shown := make([]string, 0, len(supported))
	for _, v := range supported {
		shown = append(shown, strconv.Quote(clean(v, 32)))
	}
	return fmt.Errorf("server/discover: the server speaks MCP %s; doorward reads %s", strings.Join(shown, ", "), strings.Join(versions, ", "))
}

func (s *session) initialize(ctx context.Context) (Server, error) {
	raw, err := s.call(ctx, "initialize", map[string]any{
		"protocolVersion": legacy[0],
		"capabilities":    map[string]any{},
		"clientInfo":      clientInfo,
	})
	if err != nil {
		return Server{}, err
	}
	var res struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return Server{}, fmt.Errorf("initialize: the result is not a handshake: %w", err)
	}
	if !slices.Contains(legacy, res.ProtocolVersion) {
		return Server{}, fmt.Errorf("initialize: the server speaks MCP %s; doorward reads %s",
			strconv.Quote(clean(res.ProtocolVersion, 32)), strings.Join(versions, ", "))
	}
	s.version = res.ProtocolVersion
	if err := s.notify(ctx, "notifications/initialized"); err != nil {
		return Server{}, err
	}
	return Server{Name: clean(res.ServerInfo.Name, 128), Version: clean(res.ServerInfo.Version, 64), Protocol: s.version}, nil
}

// listTools reads the tool list to its last page.
func (s *session) listTools(ctx context.Context) ([]Tool, error) {
	var tools []Tool
	names := map[string]bool{}
	cursors := map[string]bool{}
	var cursor *string
	for page := 1; ; page++ {
		if page > MaxPages {
			return nil, fmt.Errorf("tools/list: the list runs past %d pages", MaxPages)
		}
		var params map[string]any
		if cursor != nil {
			params = map[string]any{"cursor": *cursor}
		}
		raw, err := s.call(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		var res struct {
			Tools      []Tool  `json:"tools"`
			NextCursor *string `json:"nextCursor"`
			ResultType string  `json:"resultType"`
		}
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("tools/list: the result is not a tool list: %w", err)
		}
		if res.ResultType != "" && res.ResultType != "complete" {
			return nil, fmt.Errorf("tools/list: the server asks for more input (%s), which listing tools does not take", strconv.Quote(clean(res.ResultType, 32)))
		}
		for _, t := range res.Tools {
			if names[t.Name] {
				return nil, fmt.Errorf("tools/list: the server lists tool %q twice", t.Name)
			}
			names[t.Name] = true
			tools = append(tools, t)
		}
		if len(tools) > MaxTools {
			return nil, fmt.Errorf("tools/list: the server lists more than %d tools", MaxTools)
		}
		if res.NextCursor == nil {
			return tools, nil
		}
		if cursors[*res.NextCursor] {
			return nil, errors.New("tools/list: the server sent the same cursor twice")
		}
		cursors[*res.NextCursor] = true
		cursor = res.NextCursor
	}
}

// rpcResponse is a JSON-RPC response, or any other message.
type rpcResponse struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

// message is one JSON-RPC message, a notification when id is 0. Under
// 2026-07-28 its params name the version and who is asking.
func (s *session) message(method string, id int, params map[string]any) map[string]any {
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if id != 0 {
		msg["id"] = id
	}
	if s.modern {
		if params == nil {
			params = map[string]any{}
		}
		params["_meta"] = map[string]any{metaVersion: ProtocolVersion, metaClientInfo: clientInfo, metaCapabilities: map[string]any{}}
	}
	if params != nil {
		msg["params"] = params
	}
	return msg
}

// call sends one request and returns its result.
func (s *session) call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	s.lastID++
	id := strconv.Itoa(s.lastID)
	res, err := s.post(ctx, method, s.message(method, s.lastID, params))
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, statusError(method, res)
	}
	if method == "initialize" {
		s.id = res.Header.Get("Mcp-Session-Id")
	}
	reply, err := readResponse(res, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	if reply.Error != nil {
		return nil, fmt.Errorf("%s: the server answered %d %s", method, reply.Error.Code, strconv.Quote(clean(reply.Error.Message, 200)))
	}
	if reply.Result == nil {
		return nil, fmt.Errorf("%s: the response has no result", method)
	}
	return reply.Result, nil
}

// notify sends a notification, which the server accepts without an answer.
func (s *session) notify(ctx context.Context, method string) error {
	res, err := s.post(ctx, method, s.message(method, 0, nil))
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode/100 != 2 {
		return statusError(method, res)
	}
	return nil
}

func (s *session) post(ctx context.Context, method string, msg any) (*http.Response, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	s.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if s.modern {
		req.Header.Set("Mcp-Method", method)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	return res, nil
}

// close ends the session, if the server opened one. The answer does not
// matter: a server may refuse to end sessions on request.
func (s *session) close(ctx context.Context) {
	if s.id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.url, nil)
	if err != nil {
		return
	}
	s.setHeaders(req)
	if res, err := client.Do(req); err == nil {
		_ = res.Body.Close()
	}
}

// setHeaders sets the caller's headers, then the protocol's, which the
// caller's cannot replace.
func (s *session) setHeaders(req *http.Request) {
	for name, values := range s.header {
		req.Header[http.CanonicalHeaderKey(name)] = values
	}
	if s.version != "" {
		req.Header.Set("MCP-Protocol-Version", s.version)
	}
	if s.id != "" {
		req.Header.Set("Mcp-Session-Id", s.id)
	}
}

// readResponse reads the response to request id: the body itself when it
// is JSON, or the first message in the event stream that answers it.
func readResponse(res *http.Response, id string) (rpcResponse, error) {
	body := &io.LimitedReader{R: res.Body, N: MaxMessage + 1}
	ct, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	switch ct {
	case "application/json":
		data, err := io.ReadAll(body)
		if err != nil {
			return rpcResponse{}, err
		}
		if body.N <= 0 {
			return rpcResponse{}, fmt.Errorf("the response is larger than %d bytes", MaxMessage)
		}
		reply, ok := answer(data, id)
		if !ok {
			return rpcResponse{}, errors.New("the body is not the response to the request")
		}
		return reply, nil
	case "text/event-stream":
		var reply rpcResponse
		found := errors.New("found")
		err := x.ReadEvents(body, MaxMessage, func(e x.Event) error {
			if r, ok := answer(e.Data, id); ok {
				reply = r
				return found
			}
			// A notification, a request the client does not serve, or the
			// stream's priming event.
			return nil
		})
		switch {
		case errors.Is(err, found):
			return reply, nil
		case body.N <= 0:
			return rpcResponse{}, fmt.Errorf("the event stream runs past %d bytes without the response", MaxMessage)
		case err != nil:
			return rpcResponse{}, err
		}
		return rpcResponse{}, errors.New("the event stream ended without the response")
	}
	return rpcResponse{}, fmt.Errorf("the response is %s, neither JSON nor an event stream", strconv.Quote(clean(ct, 64)))
}

// answer decodes data as the response to request id.
func answer(data []byte, id string) (rpcResponse, bool) {
	var r rpcResponse
	if json.Unmarshal(data, &r) != nil || r.Method != "" || string(bytes.TrimSpace(r.ID)) != id {
		return rpcResponse{}, false
	}
	return r, r.Result != nil || r.Error != nil
}

func statusError(method string, res *http.Response) error {
	if loc := res.Header.Get("Location"); res.StatusCode/100 == 3 && loc != "" {
		return fmt.Errorf("%s: the server redirects to %s; import from that address instead", method, strconv.Quote(clean(loc, 256)))
	}
	start, _ := io.ReadAll(io.LimitReader(res.Body, 200))
	return &StatusError{Method: method, Code: res.StatusCode, Status: res.Status, Body: clean(string(start), 200)}
}

// clean makes text from the server safe to print: control characters and
// other unprintable runes become spaces, and it is cut to max bytes.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, s)
	s = strings.TrimSpace(s)
	for len(s) > max {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}
